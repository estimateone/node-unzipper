const { Transform } = require('stream');
const util = require('util');

function NoopStream() {
  if (!(this instanceof NoopStream)) {
    return new NoopStream();
  }
  Transform.call(this);
}

util.inherits(NoopStream, Transform);

NoopStream.prototype._transform = function(d,e,cb) { cb() ;};

module.exports = NoopStream;
