import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.services.email_service import EmailService
from app.models.user_model import User
from app.utils.smtp_connection import SMTPClient
from app.utils.template_manager import TemplateManager
from smtplib import SMTPException

@pytest.mark.asyncio
async def test_send_user_email_success():
    # Mock TemplateManager to return fake HTML content
    template_manager_mock = MagicMock(spec=TemplateManager)
    template_manager_mock.render_template = MagicMock(return_value="<h1>Email Content</h1>")

    # Mock SMTPClient to prevent real email sending
    smtp_client_mock = MagicMock(spec=SMTPClient)
    smtp_client_mock.send_email = MagicMock(return_value=None)

    # Patch SMTPClient initialization in EmailService
    with patch('app.services.email_service.SMTPClient', return_value=smtp_client_mock):
        email_service = EmailService(template_manager=template_manager_mock)

        # Mock user data
        user_data = {
            "email": "test@example.com",
            "name": "Test User",
            "verification_url": "http://example.com/verify?token=abc123",
        }

        # Call the method
        await email_service.send_user_email(user_data, "email_verification")

        # Assertions
        template_manager_mock.render_template.assert_called_once_with(
            "email_verification", **user_data
        )
        smtp_client_mock.send_email.assert_called_once_with(
            subject="Verify Your Account",
            html_content="<h1>Email Content</h1>",
            recipient="test@example.com",
        )


@pytest.mark.asyncio
async def test_send_user_email_failure(caplog):
    # Mock TemplateManager to return fake HTML content
    template_manager_mock = MagicMock(spec=TemplateManager)
    template_manager_mock.render_template = MagicMock(return_value="<h1>Email Content</h1>")

    # Mock SMTPClient to simulate an exception
    smtp_client_mock = MagicMock(spec=SMTPClient)
    smtp_client_mock.send_email = MagicMock(side_effect=SMTPException("SMTP Error"))

    # Patch SMTPClient initialization in EmailService
    with patch('app.services.email_service.SMTPClient', return_value=smtp_client_mock):
        email_service = EmailService(template_manager=template_manager_mock)

        # Mock user data
        user_data = {
            "email": "test@example.com",
            "name": "Test User",
            "verification_url": "http://example.com/verify?token=abc123",
        }

        # Call the method and expect an exception
        with pytest.raises(SMTPException, match="SMTP Error"):
            await email_service.send_user_email(user_data, "email_verification")

        # Assertions
        assert "Failed to send email" in caplog.text
