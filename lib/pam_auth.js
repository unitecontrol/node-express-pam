
try {
  var auth = require('authenticate-pam').authenticate;
  var pam_auth = function(pamMod, user, pwd, cb) {
    var _cb = function(err) { cb(!err); };
    auth(user, pwd, _cb, {serviceName: pamMod, remoteHost: 'localhost'});
  }
} catch (e) {
  var pam_auth = require('unixlib').pamauth;
}


module.exports = function(realm, pamMod) {
  if(!pamMod) {
    if(process.platform == 'darwin'){
      pamMod = 'chkpasswd';
    }
    else if (process.platform == 'linux') {
      pamMod = 'passwd';
    }
  }
  if(!realm)
    realm = "Login Required";

  function basic_auth (req, res, next) {
    function send_auth() {
      res.header('WWW-Authenticate', 'Basic realm="' + realm + '"');
      res.send('Authentication required', 401);
    }
    if (req.headers.authorization && req.headers.authorization.search('Basic ') === 0) {
    // fetch login and password
      var b = new Buffer(req.headers.authorization.split(' ')[1], 'base64').toString().split(':');
      var username = b[0];
      var password = b[1];
      pam_auth(pamMod, username, password, function(success) {
                        if (success) {
                          next();
                        } else {
                          send_auth();
                        }
                      });
      return;
    }
    send_auth();
  }
  return basic_auth;  
};