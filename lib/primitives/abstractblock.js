/*!
 * abstractblock.js - abstract block object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const hash256 = require('bcrypto/lib/hash256');
const bio = require('bufio');
const util = require('../utils/util');
const InvItem = require('./invitem');
const consensus = require('../protocol/consensus');
const BN = require('bcrypto/lib/bn.js');

/**
 * Abstract Block
 * The class which all block-like objects inherit from.
 * @alias module:primitives.AbstractBlock
 * @abstract
 * @property {Hash} prevBlock
 * @property {Number} time
 * @property {Number} bits
 * @property {BigNumber} nonce
 * @property {Number} version
 * @property {BigNumber} size
 * @property {Number} height
 * @property {Hash} epochBlock
 * @property {Hash} merkleRoot
 * @property {Hash} extendedMetadata
 */

class AbstractBlock {
  /**
   * Create an abstract block.
   * @constructor
   */

  constructor() {
    
    this.prevBlock = consensus.ZERO_HASH;
    this.bits = 0;
    this.time = 0;
    this.reserved = 0;
    this.nonce = new BN(0);
    this.version = 1;
    this.size = new BN(0);
    this.height = 0;
    this.epochBlock = consensus.ZERO_HASH;
    this.merkleRoot = consensus.ZERO_HASH;
    this.extendedMetadata = consensus.ZERO_HASH;
    
    this.mutable = false;

    this._hash = null;
    this._hhash = null;
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  parseOptions(options) {
    assert(options, 'Block data is required.');
    assert(Buffer.isBuffer(options.prevBlock));
    assert((options.time >>> 0) === options.time);
    assert((options.bits >>> 0) === options.bits);
    assert(typeof options.nonce === 'string');
    assert((options.version >>> 0) === options.version);
    assert(typeof options.size === 'string');
    assert((options.height >>> 0) === options.bits);
    assert(Buffer.isBuffer(options.epochBlock));
    assert(Buffer.isBuffer(options.merkleRoot));
    assert(Buffer.isBuffer(options.extendedMetadata));


    this.prevBlock = options.prevBlock;
    this.time = options.time;
    this.bits = options.bits;
    this.nonce = BN.fromString(options.nonce);
    this.version = options.version;
    this.size = BN.fromString(options.size);
    this.height = options.height;
    this.epochBlock = options.epochBlock;
    this.merkleRoot = options.merkleRoot;
    this.extendedMetadata = options.extendedMetadata;

    if (options.mutable != null) {
      assert(typeof options.mutable === 'boolean');
      this.mutable = options.mutable;
    }

    return this;
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   */

  parseJSON(json) {
    assert(json, 'Block data is required.');
    assert(typeof json.prevBlock === 'string');
    assert((json.time >>> 0) === json.time);
    assert(typeof json.nonce === 'string');
    assert((json.version >>> 0) === json.version);
    assert(typeof json.size === 'string');
    assert((json.bits >>> 0) === json.bits);
    assert(typeof json.epochBlock === 'string');
    assert(typeof json.merkleRoot === 'string');
    assert(typeof json.extendedMetadata === 'string');
    
    this.prevBlock = util.fromRev(json.prevBlock);
    this.time = json.time;
    this.bits = json.bits;
    this.nonce = BN.fromString(json.nonce);
    this.version = json.version;
    this.size = BN.fromString(json.size);
    this.height = json.height;
    this.merkleRoot = util.fromRev(json.epochBlock);
    this.merkleRoot = util.fromRev(json.merkleRoot);
    this.merkleRoot = util.fromRev(json.extendedMetadata);

    return this;
  }

  /**
   * Test whether the block is a memblock.
   * @returns {Boolean}
   */

  isMemory() {
    return false;
  }

  /**
   * Clear any cached values (abstract).
   */

  _refresh() {
    this._hash = null;
    this._hhash = null;
  }

  /**
   * Clear any cached values.
   */

  refresh() {
    return this._refresh();
  }

  /**
   * Hash the block headers.
   * @param {String?} enc - Can be `'hex'` or `null`.
   * @returns {Hash|Buffer} hash
   */

  hash(enc) {
    let h = this._hash;
    if (!h) {
      const bw = bio.write(64);
      const layer3Hash = this._layer3Hash();
      const layer2Hash = this._layer2Hash(layer3Hash);
      bw.writeHash(this.prevBlock);
      bw.writeHash(layer2Hash);
      const buf = bw.render();
      h = hash256.digest(buf);
      if (!this.mutable)
        this._hash = h;
    }

    if (enc === 'hex') {
      let hex = this._hhash;
      if (!hex) {
        hex = h.toString('hex');
        if (!this.mutable)
          this._hhash = hex;
      }
      h = hex;
    }

    return h;
  }

  _layer3Hash() {
    const bw = bio.write(108);
    bw.writeU8(this.version);
    const sizeBuf = Buffer.from(this.size.toBuffer({ size: 7 })).reverse();
    bw.writeBytes(sizeBuf);
    bw.writeU32(this.height);
    bw.writeHash(this.epochBlock);
    bw.writeHash(this.merkleRoot);
    bw.writeHash(this.extendedMetadata);

    const buf = bw.render();
    return hash256.digest(buf);
  }

  _layer2Hash(layer3Hash) {
    const bw = bio.write(52);
    bw.writeU32(this.bits);
    bw.writeU48(this.time);
    bw.writeU1(this.reserved);
    const nonceBuf = Buffer.from(this.nonce.toBuffer({ size: 8 })).reverse();
    bw.writeBytes(nonceBuf);
    bw.writeHash(layer3Hash);

    const buf = bw.render();
    return hash256.digest(buf);
  }

  /**
   * Serialize the block headers.
   * @returns {Buffer}
   */

  toHead() {
    return this.writeHead(bio.write(160)).render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromHead(data) {
    return this.readHead(bio.read(data));
  }

  /**
   * Serialize the block headers.
   * @param {BufferWriter} bw
   */

  writeHead(bw) {
    bw.writeHash(this.prevBlock);
    bw.writeU32(this.bits);
    bw.writeU48(this.time);
    bw.writeU16(this.reserved);
    const nonceBuf = Buffer.from(this.nonce.toBuffer({ size: 8 })).reverse();
    bw.writeBytes(nonceBuf);
    bw.writeU8(this.version);
    const sizeBuf = Buffer.from(this.size.toBuffer({ size: 7 })).reverse();
    bw.writeBytes(sizeBuf);
    bw.writeU32(this.height);
    bw.writeHash(this.epochBlock);
    bw.writeHash(this.merkleRoot);
    bw.writeHash(this.extendedMetadata);
    return bw;
  }

  /**
   * Parse the block headers.
   * @param {BufferReader} br
   */

  readHead(br) {
    this.prevBlock = br.readHash();
    this.bits = br.readU32();
    this.time = br.readU48();
    this.reserved = br.readU16();
    const nonceBuf = br.readBytes(8);
    this.nonce = new BN(nonceBuf, 10, 'le');
    this.version = br.readU8();
    const sizeBuf = br.readBytes(7);
    this.size = new BN(sizeBuf, 10, 'le');
    this.height = br.readU32();
    this.epochBlock = br.readHash();
    this.merkleRoot = br.readHash();
    this.extendedMetadata = br.readHash();
    return this;
  }

  /**
   * Verify the block.
   * @returns {Boolean}
   */

  verify() {
    if (!this.verifyPOW())
      return false;

    if (!this.verifyBody())
      return false;

    return true;
  }

  /**
   * Verify proof-of-work.
   * @returns {Boolean}
   */

  verifyPOW() {
    return consensus.verifyPOW(this.hash(), this.bits);
  }

  /**
   * Verify the block.
   * @returns {Boolean}
   */

  verifyBody() {
    throw new Error('Abstract method.');
  }

  /**
   * Get little-endian block hash.
   * @returns {Hash}
   */

  rhash() {
    return util.revHex(this.hash());
  }

  /**
   * Convert the block to an inv item.
   * @returns {InvItem}
   */

  toInv() {
    return new InvItem(InvItem.types.BLOCK, this.hash());
  }
}

/*
 * Expose
 */

module.exports = AbstractBlock;
