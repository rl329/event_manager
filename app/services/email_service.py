from builtins import ValueError, dict, str
from settings.config import settings
from app.utils.smtp_connection import SMTPClient
from app.utils.template_manager import TemplateManager
from app.models.user_model import User
import logging
import smtplib

logger = logging.getLogger(__name__)


class EmailService:
    def __init__(self, template_manager: TemplateManager):
        self.smtp_client = SMTPClient(
            server=settings.smtp_server,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
        )
        self.template_manager = template_manager

    async def send_user_email(self, user_data: dict, email_type: str):
        # Map email types to subject lines
        subject_map = {
            "email_verification": "Verify Your Account",
            "password_reset": "Password Reset Instructions",
            "account_locked": "Account Locked Notification",
        }

        if email_type not in subject_map:
            raise ValueError("Invalid email type")

        try:
            # Render email content
            html_content = self.template_manager.render_template(email_type, **user_data)

            # Send the email using the SMTP client
            self.smtp_client.send_email(
                subject=subject_map[email_type],
                html_content=html_content,
                recipient=user_data["email"],
            )

            logger.info(f"Email sent successfully to {user_data['email']} for {email_type}")

        except smtplib.SMTPException as e:
            logger.error(f"Failed to send email to {user_data['email']}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in sending email: {e}")
            raise

    async def send_verification_email(self, user: User):
        verification_url = f"{settings.server_base_url}verify-email/{user.id}/{user.verification_token}"
        user_data = {
            "name": user.first_name,
            "verification_url": verification_url,
            "email": user.email,
        }
        await self.send_user_email(user_data, "email_verification")
