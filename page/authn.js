var TESTAUTHN = (function ($) {
  var my = {};

  var cred = null;

  // POST the credential to the test server, just because we can
  function postCredential(cred, result) {
    credInfo = {
      id: cred.id,
      type: cred.type,
      attestation: btoa(String.fromCharCode.apply(
        null, new Uint8Array(cred.response.attestationObject))),
      clientData: btoa(String.fromCharCode.apply(
        null, new Uint8Array(cred.response.clientDataJSON))),
    };

    $.post('/api/login_info', JSON.stringify(credInfo), function(data, stat, xhr) {
      console.log('Posted credential ' + stat);
    }, 'json');
  };

  // Given a set of credential parameters provided from the server, request the
  // authenticator create a new credential on our behalf.
	// Use the native webauthn API, and call a result handler when the process is done.
  function createCredential(params, result) {
		credOptions = {
      publicKey: {
        // Relaying party
        rp: {
          name: params.relyingPartyName,
        },

        // User parameters
        user: {
          id: params.userIdBuffer,
          name: params.userName,
          displayName: params.displayName,
        },

        // Credential Parameters. Note that this is an array, but we ONLY allow
        // ECC keys. No RSA fallback.
        pubKeyCredParams: [{
          type: 'public-key',
          alg: -7, // ECC
        }],

        // Enforce that we use the platform authenticator
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
        },

        // Challenge we use to avoid attestation replay
        challenge: params.challengeBuffer,

        // Force attestation certificate chain to be generated
        attestation: "direct",
      }
    };

    // Generate the credential
    navigator.credentials.create(credOptions).then(function(cred) {
      cred = cred;
      // Post the creds to our "backend"
      postCredential(cred, function () {});
      result(cred);
    });
  };

  function checkHasCredential(result) {
    $.getJSON('/api/login_info', function (data) {
      if (!data.credential) {
        console.log('There is no existing credential');
      }
      result(!!data.credential);
    });
  }

  // Create a credential if there isn't already one
  function doCreateCredential() {
    $.getJSON('/api/login_info', function (data) {
      if (!data.credential) {
        console.log('No credential out there, so let\'s make one.');
        data.challengeBuffer = Uint8Array.from(atob(data.challenge), c => c.charCodeAt(0)).buffer;
        data.userIdBuffer = Uint8Array.from(atob(data.userId), c => c.charCodeAt(0)).buffer;
        createCredential(data);
      } else {
        console.log('Credential already exists, aborting.');
      }
    });
  }

  // Publish our module interface
  my.CheckHasCredential = checkHasCredential;
  my.CreateCredential = doCreateCredential;

  return my;
}(jQuery));

// Update the DOM and insert events, once all is said and done.
$(window).on('load', function () {
  $('#create-id').on('click', function() {
    TESTAUTHN.CreateCredential();
  });
});

