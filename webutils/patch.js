function base64ToUint8(base64) {
	let raw = window.atob(base64);
	let rawLength = raw.length;
	let array = new Uint8Array(new ArrayBuffer(rawLength));

	for (let i = 0; i < rawLength; i++) {
	  array[i] = raw.charCodeAt(i);
	}

	return array;
}

function stringify(credReq, spaces) {
	spaces = spaces || 4;

	return JSON.stringify(credReq, (k, v) => {
		if (v instanceof ArrayBuffer) {
			return processArrayBuffer(v);
		} else if (v instanceof Uint8Array) {
			return processUint8Array(v);
		} else if (v instanceof PublicKeyCredential) {
			return processPublicKeyCredential(v);
		} else if (v instanceof AuthenticatorAttestationResponse) {
			return processAuthenticatorAttestationResponse(v);
		} else if (v instanceof AuthenticatorAssertionResponse) {
			return processAuthenticatorAssertionResponse(v);
		} else {
			return v;
		}
	}, spaces);
}

function processArrayBuffer(ab) {
	// return `ArrayBuffer[${new Uint8Array(ab)}]`;
	return new Uint8Array(ab);
}

function processUint8Array(u8a) {
	return `Uint8Array[${u8a}]`;
}

function processPublicKeyCredential(pkc) {
	return {
		id: pkc.id,
		rawId: pkc.rawId,
		response: pkc.response,
		type: pkc.type
	};
}

function processAuthenticatorAssertionResponse(aar) {
	return {
		authenticatorData: aar.authenticatorData,
		clientDataJSON: aar.clientDataJSON,
		signature: aar.signature,
		userHandle: aar.userHandle
	}
}

function processAuthenticatorAttestationResponse(aar) {
	return {
		attestationObject: aar.attestationObject,
		clientDataJSON: aar.clientDataJSON
	}
}

if (window["credCreate"] === undefined) {
	window["credCreate"] = CredentialsContainer.prototype.create;
}

CredentialsContainer.prototype.create = async function(opts) {
	console.log(opts, stringify(opts));

	let resp = await fetch("/__wsa/webauthn/default/create", {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: stringify(opts)
	});
	let json = await resp.json();

	console.log(json, stringify(json));

	return json;
}

if (window["credGet"] === undefined) {
	window["credGet"] = CredentialsContainer.prototype.get;
}

CredentialsContainer.prototype.get = async function(opts) {
	console.log(opts, stringify(opts));

	let resp = await fetch("/__wsa/webauthn/default/get", {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: stringify(opts)
	});
	let json = await resp.json();
	
	console.log(json, stringify(json));

	return json;
}
