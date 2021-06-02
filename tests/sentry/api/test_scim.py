import pytest
from django.urls import reverse

from sentry.models import (
    AuthProvider,
    InviteStatus,
    OrganizationMember,
    OrganizationMemberTeam,
    Team,
    TeamStatus,
)
from sentry.testutils import APITestCase

CREATE_USER_POST_DATA = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "test.user@okta.local",
    "name": {"givenName": "Test", "familyName": "User"},
    "emails": [{"primary": True, "value": "test.user@okta.local", "type": "work"}],
    "displayName": "Test User",
    "locale": "en-US",
    "externalId": "00ujl29u0le5T6Aj10h7",
    "groups": [],
    "password": "1mz050nq",
    "active": True,
}

CREATE_GROUP_POST_DATA = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Test SCIMv2",
    "members": [],
}


class SCIMUserTestsPermissions(APITestCase):
    def setUp(self):
        super().setUp()
        self.login_as(user=self.user)

    def test_cant_use_scim(self):
        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(url)
        assert response.status_code == 403

    def test_cant_use_scim_even_with_authprovider(self):
        AuthProvider.objects.create(organization=self.organization, provider="dummy")
        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(url)
        assert response.status_code == 403


class SCIMUserTests(APITestCase):
    def setUp(self):
        super().setUp()
        auth_provider = AuthProvider.objects.create(
            organization=self.organization, provider="dummy"
        )
        with self.feature({"organizations:sso-scim": True}):
            auth_provider.enable_scim(self.user)
            auth_provider.save()
        self.login_as(user=self.user)

    def test_user_flow(self):

        # test OM to be created does not exist

        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(
            f"{url}?startIndex=1&count=100&filter=userName%20eq%20%22test.user%40okta.local%22"
        )
        correct_get_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 0,
            "Resources": [],
        }
        assert response.status_code == 200, response.content
        assert response.data == correct_get_data

        # test that post creates an OM

        response = self.client.post(url, CREATE_USER_POST_DATA)
        org_member_id = OrganizationMember.objects.get(
            organization=self.organization, email="test.user@okta.local"
        ).id
        correct_post_data = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": org_member_id,
            "userName": "test.user@okta.local",
            # "name": {"givenName": "Test", "familyName": "User"},
            "emails": [{"primary": True, "value": "test.user@okta.local", "type": "work"}],
            # "displayName": "Test User",
            # "locale": "en-US",
            # "externalId": "00ujl29u0le5T6Aj10h7",
            "active": True,
            "name": {"familyName": "N/A", "givenName": "N/A"},
            # "groups": [],
            "meta": {"resourceType": "User"},
        }
        assert response.status_code == 201, response.content

        assert correct_post_data == response.data

        # test that response 409s if member already exists (by email)

        response = self.client.post(url, CREATE_USER_POST_DATA)
        assert response.status_code == 409, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": "User already exists in the database.",
        }

        # test that the OM is listed in the GET

        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(
            f"{url}?startIndex=1&count=100&filter=userName%20eq%20%22test.user%40okta.local%22"
        )
        correct_get_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 1,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "id": org_member_id,
                    "userName": "test.user@okta.local",
                    "emails": [{"primary": True, "value": "test.user@okta.local", "type": "work"}],
                    "name": {"familyName": "N/A", "givenName": "N/A"},
                    "active": True,
                    "meta": {"resourceType": "User"},
                }
            ],
        }
        assert response.status_code == 200, response.content
        assert response.data == correct_get_data

        # test that the OM exists when querying the id directly
        url = reverse(
            "sentry-scim-organization-members-details", args=[self.organization.slug, org_member_id]
        )
        response = self.client.get(url)
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": org_member_id,
            "userName": "test.user@okta.local",
            "emails": [{"primary": True, "value": "test.user@okta.local", "type": "work"}],
            "name": {"familyName": "N/A", "givenName": "N/A"},
            "active": True,
            "meta": {"resourceType": "User"},
        }

        # test that the OM is deleted after setting inactive to false

        url = reverse(
            "sentry-scim-organization-members-details", args=[self.organization.slug, org_member_id]
        )

        patch_req = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": False}}],
        }
        response = self.client.patch(url, patch_req)

        assert response.status_code == 204, response.content

        with pytest.raises(OrganizationMember.DoesNotExist):
            OrganizationMember.objects.get(organization=self.organization, id=org_member_id)

        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(
            f"{url}?startIndex=1&count=100&filter=userName%20eq%20%22test.user%40okta.local%22"
        )
        correct_get_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 0,
            "Resources": [],
        }
        assert response.status_code == 200, response.content
        assert response.data == correct_get_data

        # test that directly GETing and PATCHing the deleted orgmember returns 404
        url = reverse(
            "sentry-scim-organization-members-details", args=[self.organization.slug, org_member_id]
        )

        response = self.client.patch(url, patch_req)
        assert response.status_code == 404, response.content
        # assert response.data == {
        #     "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        #     "detail": "User not found.",
        # } # TODO: see if we can get away without having error schemas

        # # TODO: test authidentity is deleted
        # with pytest.raises(OrganizationMember.DoesNotExist):
        #     OrganizationMember.objects.get(organization=self.organization, id=2)

    def test_delete_route(self):
        member = self.create_member(user=self.create_user(), organization=self.organization)
        url = reverse(
            "sentry-scim-organization-members-details", args=[self.organization.slug, member.id]
        )
        response = self.client.delete(url)
        assert response.status_code == 204, response.content
        with pytest.raises(OrganizationMember.DoesNotExist):
            OrganizationMember.objects.get(organization=self.organization, id=member.id)

    # Disabling below test for now.
    # need to see what Okta admins would expect to happen with invited members
    # def test_request_invite_members_not_in_requests(self):
    #     member1 = self.create_member(user=self.create_user(), organization=self.organization)
    #     member1.invite_status = InviteStatus.REQUESTED_TO_BE_INVITED.value
    #     member1.save()

    #     member2 = self.create_member(user=self.create_user(), organization=self.organization)
    #     member2.invite_status = InviteStatus.REQUESTED_TO_JOIN.value
    #     member2.save()

    #     member3 = self.create_member(user=self.create_user(), organization=self.organization)
    #     member3.invite_status = InviteStatus.APPROVED.value  # default val
    #     member3.save()

    #     url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
    #     response = self.client.get(f"{url}?startIndex=1&count=100")
    #     assert response.status_code == 200, response.content
    #     assert response.data["totalResults"] == 2

    #     url = reverse(
    #         "sentry-scim-organization-members-details", args=[self.organization.slug, member1.id]
    #     )
    #     response = self.client.get(url)
    #     assert response.status_code == 404, response.content

    #     url = reverse(
    #         "sentry-scim-organization-members-details", args=[self.organization.slug, member2.id]
    #     )
    #     response = self.client.get(url)
    #     assert response.status_code == 404, response.content

    def test_overflow_cases(self):
        member = self.create_member(user=self.create_user(), organization=self.organization)
        url = reverse(
            "sentry-scim-organization-members-details",
            args=[self.organization.slug, "010101001010101011001010101011"],
        )
        response = self.client.get(
            url,
        )
        assert response.status_code == 404, response.content
        response = self.client.patch(url, {})
        assert response.status_code == 404, response.content
        response = self.client.delete(url, member.id)
        assert response.status_code == 404, response.content

    def test_cant_delete_only_owner_route(self):
        member_om = OrganizationMember.objects.get(
            organization=self.organization, user_id=self.user.id
        )
        url = reverse(
            "sentry-scim-organization-members-details",
            args=[self.organization.slug, member_om.id],
        )
        response = self.client.delete(url)
        assert response.status_code == 403, response.content

    def test_cant_delete_only_owner_route_patch(self):
        member_om = OrganizationMember.objects.get(
            organization=self.organization, user_id=self.user.id
        )
        patch_req = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": False}}],
        }
        url = reverse(
            "sentry-scim-organization-members-details",
            args=[self.organization.slug, member_om.id],
        )
        response = self.client.patch(url, patch_req)
        assert response.status_code == 403, response.content

    def test_pagination(self):
        for i in range(0, 150):
            user = self.create_user(is_superuser=False)
            self.create_member(user=user, organization=self.organization, role="member", teams=[])

        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(f"{url}?startIndex=1&count=100")
        assert response.data["totalResults"] == 151
        assert response.data["itemsPerPage"] == 100
        assert response.data["startIndex"] == 1
        assert len(response.data["Resources"]) == 100

        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(f"{url}?startIndex=40&count=100")
        assert response.data["totalResults"] == 151
        assert response.data["itemsPerPage"] == 100
        assert response.data["startIndex"] == 40
        assert len(response.data["Resources"]) == 100

        url = reverse("sentry-scim-organization-members-index", args=[self.organization.slug])
        response = self.client.get(f"{url}?startIndex=101&count=100")
        assert len(response.data["Resources"]) == 51
        assert response.data["totalResults"] == 151
        assert response.data["itemsPerPage"] == 51
        assert response.data["startIndex"] == 101

    # TODO: test patch with bad op


class SCIMGroupTests(APITestCase):
    def setUp(self):
        super().setUp()
        auth_provider = AuthProvider.objects.create(
            organization=self.organization, provider="dummy"
        )
        with self.feature({"organizations:sso-scim": True}):
            auth_provider.enable_scim(self.user)
            auth_provider.save()
        self.login_as(user=self.user)

    def test_group_flow(self):
        member1 = self.create_member(user=self.create_user(), organization=self.organization)
        member2 = self.create_member(user=self.create_user(), organization=self.organization)
        # test index route returns empty list
        url = reverse("sentry-scim-organization-team-index", args=[self.organization.slug])
        response = self.client.get(f"{url}?startIndex=1&count=100")
        correct_get_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 0,
            "startIndex": 1,
            "itemsPerPage": 0,
            "Resources": [],
        }
        assert response.status_code == 200, response.content
        assert response.data == correct_get_data

        # test team route 404s
        url = reverse(
            "sentry-scim-organization-team-details",
            args=[self.organization.slug, 2],
        )
        response = self.client.get(url)
        assert response.status_code == 404, response.content
        assert response.data == {
            "detail": "Group not found.",
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        }
        # test team creation
        url = reverse(
            "sentry-scim-organization-team-index",
            args=[self.organization.slug],
        )
        response = self.client.post(url, CREATE_GROUP_POST_DATA)
        assert response.status_code == 201, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": 2,
            "displayName": "test-scimv2",
            "members": [],
            "meta": {"resourceType": "Group"},
        }

        # test team details GET
        url = reverse(
            "sentry-scim-organization-team-details",
            args=[self.organization.slug, 2],
        )
        response = self.client.get(url)
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": 2,
            "displayName": "test-scimv2",
            "members": [],
            "meta": {"resourceType": "Group"},
        }

        # test team index GET
        url = reverse("sentry-scim-organization-team-index", args=[self.organization.slug])
        response = self.client.get(f"{url}?startIndex=1&count=100")
        response = self.client.get(url)
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 1,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "id": 2,
                    "displayName": "test-scimv2",
                    "members": [],
                    "meta": {"resourceType": "Group"},
                }
            ],
        }

        # update a team name
        url = reverse("sentry-scim-organization-team-details", args=[self.organization.slug, 2])
        response = self.client.patch(
            url,
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {
                        "op": "replace",
                        "value": {
                            "id": 2,
                            "displayName": "newName",
                        },
                    }
                ],
            },
        )
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": 2,
            "displayName": "newname",
            "members": None,
            "meta": {"resourceType": "Group"},
        }
        # assert slug exists
        assert Team.objects.filter(organization=self.organization, slug="newname").exists()

        # Add a member to a team

        url = reverse("sentry-scim-organization-team-details", args=[self.organization.slug, 2])
        response = self.client.patch(
            url,
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {
                        "op": "add",
                        "path": "members",
                        "value": [
                            {
                                "value": member1.id,
                                "display": member1.email,
                            }
                        ],
                    },
                ],
            },
        )
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": 2,
            "displayName": "newname",
            "members": None,
            "meta": {"resourceType": "Group"},
        }
        assert OrganizationMemberTeam.objects.filter(
            team_id=2, organizationmember_id=member1.id
        ).exists()

        # remove a member from a team

        url = reverse("sentry-scim-organization-team-details", args=[self.organization.slug, 2])
        response = self.client.patch(
            url,
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {
                        "op": "remove",
                        "path": 'members[value eq "2"]',
                    }
                ],
            },
        )
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": 2,
            "displayName": "newname",
            "members": None,
            "meta": {"resourceType": "Group"},
        }
        assert not OrganizationMemberTeam.objects.filter(
            team_id=2, organizationmember_id=member1.id
        ).exists()

        # replace the entire member list

        member3 = self.create_member(user=self.create_user(), organization=self.organization)
        OrganizationMemberTeam.objects.create(organizationmember=member3, team_id=2)
        url = reverse("sentry-scim-organization-team-details", args=[self.organization.slug, 2])
        response = self.client.patch(
            url,
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {
                        "op": "replace",
                        "path": "members",
                        "value": [
                            {
                                "value": member1.id,
                                "display": "test.user@okta.local",
                            },
                            {
                                "value": member2.id,
                                "display": "test.user@okta.local",
                            },
                        ],
                    }
                ],
            },
        )
        assert response.status_code == 200, response.content
        assert response.data == {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": 2,
            "displayName": "newname",
            "members": None,
            "meta": {"resourceType": "Group"},
        }
        assert OrganizationMemberTeam.objects.filter(
            team_id=2, organizationmember_id=member1.id
        ).exists()
        assert OrganizationMemberTeam.objects.filter(
            team_id=2, organizationmember_id=member2.id
        ).exists()

        assert not OrganizationMemberTeam.objects.filter(
            team_id=2, organizationmember_id=member3.id
        ).exists()

        # test index route returns with members
        url = reverse("sentry-scim-organization-team-index", args=[self.organization.slug])
        response = self.client.get(f"{url}?startIndex=1&count=100")
        correct_get_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "startIndex": 1,
            "itemsPerPage": 1,
            "Resources": [
                {
                    "displayName": "newname",
                    "id": 2,
                    "members": [
                        {"display": "ffadfcaad01f4c3e9e9bd9224988966c@example.com", "value": "2"},
                        {"display": "2d1585aab9c04e7b90a8e2e479a89e5f@example.com", "value": "3"},
                    ],
                    "meta": {"resourceType": "Group"},
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                }
            ],
        }
        assert response.status_code == 200, response.content
        assert response.data == correct_get_data

        # delete the team
        url = reverse("sentry-scim-organization-team-details", args=[self.organization.slug, 2])
        response = self.client.delete(url)
        assert response.status_code == 204, response.content

        assert Team.objects.get(id=2).status == TeamStatus.PENDING_DELETION


# TODO: test adding member that doesn't exist to a team
# TODO: convert team id to use var
# TODO: try to get, delete patch team that doesnt exist
