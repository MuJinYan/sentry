from io import BytesIO
from urllib.parse import urlencode

from sentry.models import EventAttachment, File
from sentry.testutils import APITestCase
from sentry.testutils.silo import region_silo_test


@region_silo_test
class GroupEventAttachmentsTest(APITestCase):
    def create_attachment(self, type=None):
        if type is None:
            type = "event.attachment"

        self.file = File.objects.create(name="hello.png", type=type)
        self.file.putfile(BytesIO(b"File contents here"))

        self.attachment = EventAttachment.objects.create(
            event_id=self.event.event_id,
            project_id=self.event.project_id,
            group_id=self.group.id,
            file_id=self.file.id,
            type=self.file.type,
            name="hello.png",
        )

        return self.attachment

    def path(self, types=None):
        path = f"/api/0/issues/{self.group.id}/attachments/"

        query = [("types", t) for t in types or ()]
        if query:
            path += "?" + urlencode(query)

        return path

    def test_basic(self):
        self.login_as(user=self.user)

        attachment = self.create_attachment()

        with self.feature("organizations:event-attachments"):
            response = self.client.get(self.path())

        assert response.status_code == 200, response.content
        assert len(response.data) == 1
        assert response.data[0]["id"] == str(attachment.id)

    def test_filter(self):
        self.login_as(user=self.user)

        self.create_attachment(type="event.attachment")
        attachment2 = self.create_attachment(type="event.minidump")

        with self.feature("organizations:event-attachments"):
            response = self.client.get(self.path(types=["event.minidump"]))

        assert response.status_code == 200, response.content
        assert len(response.data) == 1
        assert response.data[0]["id"] == str(attachment2.id)

    def test_without_feature(self):
        self.login_as(user=self.user)
        self.create_attachment()

        with self.feature({"organizations:event-attachments": False}):
            response = self.client.get(self.path())

        assert response.status_code == 404, response.content
