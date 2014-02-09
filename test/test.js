var assert = require("assert");


var lzf = require("../index.js");


var lorem = "Lorem ipsum dolor sit amet, consectetur adipiscing elit." +
    "Curabitur volutpat, nulla nec egestas semper," +
    "ante dui tristique nibh, quis feugiat.";

var loremBuffer = new Buffer(lorem);
var loremCompressed = lzf.compress(loremBuffer);
var loremDecompressed = lzf.decompress(loremCompressed);

assert.equal(loremDecompressed.toString(), lorem);
console.log("test ok");

var crc = lzf.crc32(loremBuffer);
var crcS = lzf.crc32(loremBuffer, 223123);

console.log("crc: " + crc + "  " + crcS);

