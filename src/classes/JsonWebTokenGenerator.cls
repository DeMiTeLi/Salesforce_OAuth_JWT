public class JsonWebTokenGenerator {
	String iss;
	String sub;
	String aud;
	String endPoint;
	public JsonWebTokenGenerator(String iss, String sub, String aud, String endPoint) {
		this.iss = iss;
		this.sub = sub;
		this.aud = aud;
		this.endPoint = endPoint;
	}

	public String generateWebToken() {
		// Static resource to get the key which will be used for Crypto-Sign
		StaticResource jwtPrivateResource = [SELECT Id, Body FROM StaticResource WHERE Name = 'JWT_Private_Key' LIMIT 1];
		String privateKey = jwtPrivateResource.Body.toString();

		// Create Body if the JSON that contains endpont URL, Cosumer Key, Type
		JSONGenerator jsonHeader = JSON.createGenerator(false);
		jsonHeader.writeStartObject();
		jsonHeader.writeStringField('alg', 'RS256');
		jsonHeader.writeStringField('type', 'JWT');
		jsonHeader.writeEndObject();
		String encodedHeader = EncodingUtil.base64Encode(Blob.valueOf(jsonHeader.getAsString()));

		JSONGenerator jsonBody = JSON.createGenerator(false);
		jsonBody.writeStartObject();
		jsonBody.writeStringField('iss', iss);
		jsonBody.writeStringField('sub', sub);
		jsonBody.writeStringField('aud', aud);
		jsonBody.writeNumberField('exp', DateTime.now().addMinutes(3).getTime());
		String encodedBody = EncodingUtil.base64Encode(Blob.valueOf(jsonBody.getAsString()));

		String jwtRequest = encodedHeader + '.' + encodedBody;

		// Sign the Json Web Token
		Blob cryptoKey = EncodingUtil.base64Decode(privateKey);
		Blob rs256sig = Crypto.sign('RSA-SHA256', Blob.valueOf(jwtRequest), cryptoKey);
		String signature = EncodingUtil.base64Encode(rs256sig);
		signature = signature.replace('+', '-');
		signature = signature.replace('/', '_');

		String signedJwtRequest = jwtRequest + '.' + signature;
		System.debug('signedJwtRequest ::: ' + signedJwtRequest);

		// Create payload
		String payload = 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer';
		payload += '&assertion=' + signedJwtRequest;

		// Create a HttpRequest and send it to server
		Http httpObj = new Http();
		HttpRequest req = new HttpRequest();
		HttpResponse resp = new HttpResponse();
		req.setEndpoint(endPoint);
		req.setMethod('POST');
		req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
		req.setBody(payload);
		resp = httpObj.send(req);

		System.debug('res.getStatus() ::: ' + resp.getStatus());
		System.debug('res.getBody() ::: ' + resp.getBody());

		if (resp.getStatusCode() == 200) {
			Map<String, Object> mapTokenResponse = (Map<String, Object>) JSON.deserializeUntyped(resp.getBody());
			return (String)mapTokenResponse.get('access_token');
		}

		return resp.getBody();
	}
}