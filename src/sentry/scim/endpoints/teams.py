import logging
import re
from uuid import uuid4

from django.db import IntegrityError, transaction
from django.template.defaultfilters import slugify
from rest_framework import serializers, status
from rest_framework.response import Response

from sentry.api.bases.organization import OrganizationEndpoint
from sentry.api.endpoints.team_details import TeamSerializer
from sentry.api.exceptions import ResourceDoesNotExist
from sentry.api.paginator import GenericOffsetPaginator
from sentry.api.serializers import serialize
from sentry.api.serializers.models.team import TeamSCIMSerializer
from sentry.models import (
    AuditLogEntryEvent,
    OrganizationMember,
    OrganizationMemberTeam,
    Team,
    TeamStatus,
)
from sentry.signals import team_created
from sentry.tasks.deletion import delete_team

from .constants import SCIM_404_GROUP_RES
from .utils import SCIMEndpoint, parse_filter_conditions

# from sentry.utils.sdk import bind_organization_context  # TODO: do i need this?


delete_logger = logging.getLogger("sentry.deletions.api")


CONFLICTING_SLUG_ERROR = "A team with this slug already exists."

# TODO: write tests
# TODO: must rectify permissions between scim and team endpoints
# TODO: GET index filtering?
# TODO: Correct error responses
# TODO: what to name the routes in the code?
# TODO: add prefix to all url routes
# TODO: does it matter team 404 doesn't include error schema?
# TODO: serialize ids // return strings as ids?
# TODO: dont enable PUTs on these routes?
# TODO: testing with okta
# TODO: what should a PATCH failure do?
# TODO: users: inactive users -- remove them from the SCIM queries
# TODO: docs: add notes about lowercaseing of emails, and slugification of teams/groups


class OrganizationSCIMTeamIndex(SCIMEndpoint, OrganizationEndpoint):
    def get(self, request, organization):
        # if request.auth and hasattr(request.auth, "project"):
        #     return Response(status=403)

        # TODO: is filter support needed on this route? Okta docs say no.
        # filter_val = parse_filter_conditions(request.GET.get("filter"))

        queryset = Team.objects.filter(
            organization=organization, status=TeamStatus.VISIBLE
        ).order_by("slug")

        def data_fn(offset, limit):
            return list(queryset[offset : offset + limit])

        return self.paginate(
            request=request,
            on_results=lambda results: serialize(results, None, TeamSCIMSerializer()),
            paginator=GenericOffsetPaginator(data_fn=data_fn),
            default_per_page=int(request.GET.get("count", 100)),
            queryset=queryset,
        )

    def post(self, request, organization):
        serializer = SCIMGroupSerializer(data={"name": request.data["displayName"]})

        if serializer.is_valid():
            result = serializer.validated_data

            try:
                with transaction.atomic():
                    team = Team.objects.create(
                        name=result.get("name"),
                        organization=organization,
                    )
            except IntegrityError:
                return Response(
                    {
                        "non_field_errors": [CONFLICTING_SLUG_ERROR],
                        "detail": CONFLICTING_SLUG_ERROR,
                    },
                    status=409,
                )
            else:
                team_created.send_robust(
                    organization=organization, user=request.user, team=team, sender=self.__class__
                )

            self.create_audit_entry(
                request=request,
                organization=organization,
                target_object=team.id,
                event=AuditLogEntryEvent.TEAM_ADD,
                data=team.get_audit_log_data(),
            )
            context = serialize(team, serializer=TeamSCIMSerializer())
            return Response(context, status=201)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrganizationSCIMTeamDetails(SCIMEndpoint, OrganizationEndpoint):
    def _get_team(self, organization, team_id):
        try:
            team = (
                Team.objects.filter(organization=organization, id=team_id)
                .select_related("organization")  # TODO: do we need select_related here?
                .get()
            )
        except Team.DoesNotExist:
            raise ResourceDoesNotExist
        except AssertionError as error:
            if str(error) == "value too large":
                raise ResourceDoesNotExist
            raise error
        if team.status != TeamStatus.VISIBLE:
            raise ResourceDoesNotExist
        return team

    def get(self, request, organization, team_id):
        try:
            team = self._get_team(organization, team_id)
        except ResourceDoesNotExist:
            return Response(SCIM_404_GROUP_RES, status=404)
        context = serialize(team, serializer=TeamSCIMSerializer())
        return Response(context)

    def patch(self, request, organization, team_id):
        try:
            team = self._get_team(organization, team_id)
        except ResourceDoesNotExist:
            return Response(SCIM_404_GROUP_RES, status=404)

        for operation in request.data.get("Operations", []):
            if operation["op"] == "add" and operation["path"] == "members":
                for member in operation["value"]:
                    try:
                        member = OrganizationMember.objects.get(
                            organization=team.organization, id=member["value"]
                        )
                    except OrganizationMember.DoesNotExist:
                        # TODO: raise an error?
                        pass
                    try:
                        with transaction.atomic():  # TODO: should we do _all_ of these in 1 transaction? look at scim spec and see what it says
                            omt = OrganizationMemberTeam.objects.create(
                                team=team, organizationmember=member
                            )
                        self.create_audit_entry(
                            request=request,
                            organization=organization,
                            target_object=omt.id,
                            target_user=member.user,
                            event=AuditLogEntryEvent.MEMBER_JOIN_TEAM,
                            data=omt.get_audit_log_data(),
                        )
                    except IntegrityError:
                        # TODO: what to do here?
                        pass
            elif operation["op"] == "remove" and "members" in operation["path"]:

                parsed_filter = parse_filter_conditions(
                    re.search(r"\[(.*?)\]", operation["path"]).groups()[0]
                )
                # TODO: how can above fail?
                try:
                    member = OrganizationMember.objects.get(
                        organization=team.organization, id=parsed_filter[0]
                    )
                except OrganizationMember.DoesNotExist:
                    # TODO: 404?
                    pass
                with transaction.atomic():
                    try:
                        omt = OrganizationMemberTeam.objects.get(
                            team=team, organizationmember=member
                        )
                    except OrganizationMemberTeam.DoesNotExist:
                        pass
                    else:
                        self.create_audit_entry(
                            request=request,
                            organization=organization,
                            target_object=omt.id,
                            target_user=member.user,
                            event=AuditLogEntryEvent.MEMBER_LEAVE_TEAM,
                            data=omt.get_audit_log_data(),
                        )
                        omt.delete()
            elif operation["op"] == "replace" and operation.get("path", None) is None:
                serializer = TeamSerializer(
                    team,
                    data={
                        "slug": slugify(operation["value"]["displayName"]),
                    },
                    partial=True,
                )
                if serializer.is_valid():
                    team = serializer.save()
                    self.create_audit_entry(
                        request=request,
                        organization=team.organization,
                        target_object=team.id,
                        event=AuditLogEntryEvent.TEAM_EDIT,
                        data=team.get_audit_log_data(),
                    )
            elif operation["op"] == "replace" and operation["path"] == "members":
                try:
                    with transaction.atomic():
                        # delete all the current team members and add the ones in the list
                        queryset = OrganizationMemberTeam.objects.filter(team_id=team.id)
                        queryset.delete()
                        for member in operation["value"]:
                            try:
                                member = OrganizationMember.objects.get(
                                    organization=team.organization, id=member["value"]
                                )
                            except OrganizationMember.DoesNotExist:
                                # TODO: raise an error?
                                pass
                            OrganizationMemberTeam.objects.create(
                                team=team, organizationmember=member
                            )
                except IntegrityError:
                    # TODO: what to do here?
                    pass
        # For a patch request, we don't need to return the full list of members
        context = serialize(team, serializer=TeamSCIMSerializer(), members_null=True)
        return Response(context)

    def delete(self, request, organization, team_id):
        try:
            team = self._get_team(organization, team_id)
        except ResourceDoesNotExist:
            return Response(SCIM_404_GROUP_RES, status=404)
        updated = Team.objects.filter(id=team.id, status=TeamStatus.VISIBLE).update(
            status=TeamStatus.PENDING_DELETION
        )
        if updated:
            transaction_id = uuid4().hex

            self.create_audit_entry(
                request=request,
                organization=team.organization,
                target_object=team.id,
                event=AuditLogEntryEvent.TEAM_REMOVE,
                data=team.get_audit_log_data(),
                transaction_id=transaction_id,
            )

            delete_team.apply_async(kwargs={"object_id": team.id, "transaction_id": transaction_id})

            delete_logger.info(
                "object.delete.queued",
                extra={
                    "object_id": team.id,
                    "transaction_id": transaction_id,
                    "model": type(team).__name__,
                },
            )

        return Response(status=204)


class SCIMGroupSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=64, required=True, allow_null=False, allow_blank=False)

    def validate(self, attrs):
        if not (attrs.get("name")):
            raise serializers.ValidationError("Name is required")
        return attrs
