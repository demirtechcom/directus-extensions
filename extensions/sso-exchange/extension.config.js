function stubOptionalDeps(stubs) {
  return {
    name: 'stub-optional-deps',
    resolveId(id) {
      if (Object.prototype.hasOwnProperty.call(stubs, id)) {
        return '\0stub:' + id;
      }
    },
    load(id) {
      if (id.startsWith('\0stub:')) {
        const name = id.slice(6);
        return stubs[name];
      }
    },
  };
}

function polyfillNodeGlobals() {
  return {
    name: 'polyfill-node-globals',
    renderChunk(code) {
      const polyfill =
        'import{fileURLToPath as __polyfill_fup}from"url";' +
        'import{dirname as __polyfill_dn}from"path";' +
        'const __filename=__polyfill_fup(import.meta.url);' +
        'const __dirname=__polyfill_dn(__filename);\n';
      return { code: polyfill + code, map: null };
    },
  };
}

export default {
  plugins: [
    stubOptionalDeps({
      'mock-aws-s3': 'export default {}',
      'nock': 'export default function nock() { return {}; }',
      'aws-sdk': 'export default {}',
    }),
    polyfillNodeGlobals(),
  ],
};
