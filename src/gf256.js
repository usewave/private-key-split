class GF256 {
  static FIELD_SIZE = 256;
  static PRIMITIVE_POLY = 0x11d; // x^8 + x^4 + x^3 + x + 1

  static LOG_TABLE = GF256.initLogTable();
  static EXP_TABLE = GF256.initExpTable();

  static initLogTable() {
    const table = new Array(256).fill(0);
    let x = 1;
    for (let i = 0; i < 255; i++) {
      table[x] = i;
      x = GF256.multiplyWithoutTables(x, 2);
    }
    return table;
  }

  static initExpTable() {
    const table = new Array(256).fill(0);
    let x = 1;
    for (let i = 0; i < 255; i++) {
      table[i] = x;
      x = GF256.multiplyWithoutTables(x, 2);
    }
    table[255] = table[0];
    return table;
  }

  static multiplyWithoutTables(a, b) {
    let result = 0;
    let temp = b;

    for (let i = 0; i < 8; i++) {
      if ((a & (1 << i)) !== 0) {
        result ^= temp;
      }
      const highBitSet = (temp & 0x80) !== 0;
      temp = (temp << 1) & 0xff;
      if (highBitSet) {
        temp ^= this.PRIMITIVE_POLY & 0xff;
      }
    }

    return result;
  }

  static multiply(a, b) {
    const aNum = a instanceof Uint8Array ? a[0] : a;
    const bNum = b instanceof Uint8Array ? b[0] : b;

    if (aNum === 0 || bNum === 0) return new Uint8Array([0]);

    const logA = this.LOG_TABLE[aNum];
    const logB = this.LOG_TABLE[bNum];
    const sumLog = (logA + logB) % 255;

    return new Uint8Array([this.EXP_TABLE[sumLog]]);
  }

  static add(a, b) {
    const aNum = a instanceof Uint8Array ? a[0] : a;
    const bNum = b instanceof Uint8Array ? b[0] : b;
    return new Uint8Array([aNum ^ bNum]);
  }

  static subtract(a, b) {
    return this.add(a, b); // In GF(256), addition and subtraction are the same
  }

  static pow(base, exp) {
    const baseNum = base instanceof Uint8Array ? base[0] : base;
    if (baseNum === 0) return new Uint8Array([0]);
    if (exp === 0) return new Uint8Array([1]);

    const logBase = this.LOG_TABLE[baseNum];
    const resultLog = (logBase * exp) % 255;
    return new Uint8Array([this.EXP_TABLE[resultLog]]);
  }

  static inverse(a) {
    const aNum = a instanceof Uint8Array ? a[0] : a;
    if (aNum === 0) throw new Error("Division by zero");
    if (aNum === 1) return new Uint8Array([1]);

    const logA = this.LOG_TABLE[aNum];
    const invLog = (255 - logA) % 255;
    return new Uint8Array([this.EXP_TABLE[invLog]]);
  }
}

module.exports = { GF256 };
