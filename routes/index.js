var express = require('express');
var router = express.Router();
const crypto = require('crypto');
const { spawn } = require('child_process');



const otplib = require('otplib');
const secret = 'KM2UEMCNGRBDCVZXJMYE26SHKVQTCQDC';




let h = '';

/* GET home page. */
router.get('/setfirewall', function(req, res, next) {

  crypto.randomBytes(32, (err, buffer) => {
	  h = buffer.toString();
		res.render('asktoken', { key: h });
  });

});

router.post('/setfirewall', function(req, res, next) {

	let token = req.body.token;
	let key = req.body.key;

	try {
	const isValid = otplib.authenticator.verify({ token, secret });

	console.log(isValid, req.header('x-forwarded-for'));
	    let realip = req.header('x-forwarded-for');

		if (isValid) {
			let src = '--add-source=' + realip;
			const firewall = spawn('firewall-cmd', ['--zone=work', src]);
			firewall.stdout.on('data', (data) => {
				console.log(`stdout: ${data}`);
			});
			firewall.stderr.on('data', (data) => {
			  console.error(`stderr: ${data}`);
			});

			firewall.on('close', (code) => {
			  console.log(`child process exited with code ${code}`);
				res.send({result : isValid, key: key, ip: realip, code: code});
			});

		} else {
				res.send({result : isValid, key: key, ip: realip});
		}

		/*
		const firewall = spawn('firewall-cmd', ['-zone=work', src], {
		  detached: true,
		  stdio: [ 'ignore', out, err ]
		});

		subprocess.unref();

		*/


	} catch (err) {
	  // Possible errors
	  // - options validation
	  // - "Invalid input - it is not base32 encoded string" (if thiry-two is used)
	  console.error(err);
		res.send({result : err});
	}


});


module.exports = router;