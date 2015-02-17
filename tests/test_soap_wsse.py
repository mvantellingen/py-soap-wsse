import os
import soap_wsse


KEY_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'soap_wsse_keys.pem')


XML="""
<soapenv:Envelope xmlns:mvt="http://github.com/mvantellingen"
    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <soapenv:Header></soapenv:Header>
  <soapenv:Body>
    <mvt:Function>
      <mvt:Argument>OK</mvt:Argument>
    </mvt:Function>
  </soapenv:Body>
</soapenv:Envelope>
""".strip()


def test_sign():
    signed_xml = soap_wsse.sign_envelope(XML, KEY_FILE)
    result = soap_wsse.verify_envelope(signed_xml, KEY_FILE)
    assert result is True


def test_sign_failed():
    signed_xml = soap_wsse.sign_envelope(XML, KEY_FILE)
    signed_xml = signed_xml.replace('OK', 'NOT OK!')

    result = soap_wsse.verify_envelope(signed_xml, KEY_FILE)
    assert result is False
