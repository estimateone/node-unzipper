'use strict';

module.exports = Parse.create = Parse;

var PullStream = require('pullstream');
var Stream = require('stream').Stream;
var inherits = require('util').inherits;
var zlib = require('zlib');
var Entry = require('./entry');

inherits(Parse, Stream);

function Parse() {
  var self = this;
  if (!(this instanceof Parse)) {
    return new Parse();
  }

  Stream.apply(this);

  this.writable = true;
  this.readable = true;
  this._pullStream = new PullStream();

  this._pullStream.on("error", function (e) {
    self.emit('error', e);
  });

  this._pullStream.on("end", function () {
    console.log('ps end');
    self.emit('end');
  });

  this._readRecord();
}

Parse.prototype._readRecord = function () {
  var self = this;
  this._pullStream.pull(4, function (err, data) {
    console.log('-------------------------');
    if (err) {
      return self.emit('error', err);
    }

    if (data.length === 0) {
      console.error('no data');
      return;
    }

    var signature = data.readUInt32LE(0);
    if (signature === 0x04034b50) {
      self._readFile();
    } else if (signature === 0x02014b50) {
      self._readCentralDirectoryFileHeader();
    } else if (signature === 0x06054b50) {
      self._readEndOfCentralDirectoryRecord();
    } else {
      console.error('signature error');
      self.emit('error', new Error('invalid signature: 0x' + signature.toString(16)));
    }
  });
};

Parse.prototype._readFile = function () {
  var self = this;
  this._pullStream.pull(26, function (err, data) {
    if (err) {
      return self.emit('error', err);
    }

    var compressionMethod = data.readUInt16LE(4);
    var compressedSize = data.readUInt32LE(14);
    var fileNameLength = data.readUInt16LE(22);
    var extraFieldLength = data.readUInt16LE(24);

    console.log('compressionMethod', compressionMethod);
    console.log('compressedSize', compressedSize);
    console.log('fileNameLength', fileNameLength);
    console.log('extraFieldLength', extraFieldLength);

    return self._pullStream.pull(fileNameLength, function (err, fileName) {
      if (err) {
        return self.emit('error', err);
      }
      fileName = fileName.toString('utf8');
      console.log('fileName', fileName);
      var entry = new Entry();
      entry.path = fileName;
      entry._path = fileName;
      entry.props.path = fileName;
      self.emit('entry', entry);

      self._pullStream.pull(extraFieldLength, function (err, extraField) {
        if (err) {
          return self.emit('error', err);
        }
        console.log('extraFieldStuff', extraField);
        if (compressionMethod === 0) {
          self._pullStream.pull(compressedSize, function (err, compressedData) {
            if (err) {
              return self.emit('error', err);
            }
            console.log('compressedData', compressedData.toString('utf8'));

            entry.emit('data', compressedData);

            return self._readRecord();
          });
        } else {
          var inflater = zlib.createInflateRaw();
          inflater.on('error', function(err) {
            self.emit('error', err);
          });
          inflater.on('end', function() {
            console.log('inflater end', arguments);
            self._readRecord();
          });
          inflater.on('data', function(data) {
            console.log('inflater data', data.toString('utf8'));
          });
          self._pullStream.pipe(compressedSize, inflater);
        }
      });
    });
  });
};

Parse.prototype._readCentralDirectoryFileHeader = function () {
  var self = this;
  this._pullStream.pull(42, function (err, data) {
    if (err) {
      return self.emit('error', err);
    }

    var compressionMethod = data.readUInt16LE(6);
    var compressedSize = data.readUInt32LE(16);
    var fileNameLength = data.readUInt16LE(24);
    var extraFieldLength = data.readUInt16LE(26);
    var fileCommentLength = data.readUInt16LE(28);

    console.log('compressionMethod', compressionMethod);
    console.log('compressedSize', compressedSize);
    console.log('fileNameLength', fileNameLength);
    console.log('extraFieldLength', extraFieldLength);
    console.log('fileCommentLength', fileCommentLength);

    return self._pullStream.pull(fileNameLength, function (err, fileName) {
      if (err) {
        return self.emit('error', err);
      }
      fileName = fileName.toString('utf8');
      console.log('fileName', fileName);

      self._pullStream.pull(extraFieldLength, function (err, extraField) {
        if (err) {
          return self.emit('error', err);
        }
        console.log('extraFieldStuff', extraField);
        self._pullStream.pull(fileCommentLength, function (err, fileComment) {
          if (err) {
            return self.emit('error', err);
          }
          console.log('fileComment', fileComment.toString('utf8'));
          return self._readRecord();
        });
      });
    });
  });
};

Parse.prototype._readEndOfCentralDirectoryRecord = function () {
  var self = this;
  this._pullStream.pull(18, function (err, data) {
    if (err) {
      return self.emit('error', err);
    }

    var commentLength = data.readUInt16LE(16);
    console.log('commentLength', commentLength);

    return self._pullStream.pull(commentLength, function (err, comment) {
      if (err) {
        return self.emit('error', err);
      }
      comment = comment.toString('utf8');
      console.log('comment', comment);
      return self._readRecord();
    });
  });
};

Parse.prototype.write = function (data) {
  this._pullStream.write(data);
};

Parse.prototype.end = function (data) {
  this._pullStream.end(data);
};

Parse.prototype.pipe = function (dest, opts) {
  console.error('pipe unzip.Parse -> ', dest.constructor);
  var self = this;
  if (typeof dest.add === "function") {
    self.on("entry", function (entry) {
      dest.add(entry);
    })
  }
  return Stream.prototype.pipe.apply(this, arguments)
}