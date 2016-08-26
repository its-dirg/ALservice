import smtplib
from abc import abstractmethod, ABCMeta
from email.header import Header
from email.mime.text import MIMEText


class Email(metaclass=ABCMeta):
    """
    Base class for sending a token with mail
    """

    @abstractmethod
    def send_mail(self, token: str, email_to: str):
        """
        Sends a mail
        :param token: Token to send
        :param email_to: Where to send the token
        """
        pass


class EmailSmtp(Email):
    """
    An implementation of Email using smtp
    """
    TOKEN_REPLACE = "<<token>>"

    def __init__(self, subject: str, message: str, email_from: str, smtp_server: str):
        self.subject = subject
        """:type: str"""

        self.message = message
        """:type: str"""

        self.email_from = email_from
        """:type: str"""

        self.smtp_server = smtp_server
        """:type: str"""

    def send_mail(self, token: str, email_to: str):
        """
        Sends a mail
        :param token: Token to send
        :param email_to: Where to send the token
        """
        message = self.message.replace(EmailSmtp.TOKEN_REPLACE, token)
        msg = MIMEText(message, "plain", "utf-8")
        msg['Subject'] = Header(self.subject, 'utf-8').encode()
        msg['From'] = "\"{sender}\" <{sender}>".format(sender=self.email_from)
        msg['To'] = email_to
        s = smtplib.SMTP(self.smtp_server)
        s.sendmail(self.email_from, email_to, msg.as_string())
        s.quit()
