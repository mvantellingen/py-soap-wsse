from suds.plugin import MessagePlugin

from soap_wsse import sign_envelope, verify_envelope
from soap_wsse.signing import CertificationError


class WssePlugin(MessagePlugin):
    """Suds plugin to sign soap requests with a certificate"""

    def __init__(self, filename):
        self.cert_filename = filename

    def sending(self, context):
        context.envelope = sign_envelope(context.envelope, self.cert_filename)

    def received(self, context):
        valid = verify_envelope(context.reply, self.cert_filename)
        if not valid:
            raise CertificationError("Failed to verify response")
