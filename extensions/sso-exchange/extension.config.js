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

export default {
  plugins: [
    stubOptionalDeps({
      'mock-aws-s3': 'export default {}',
      'nock': 'export default function nock() { return {}; }',
      'aws-sdk': 'export default {}',
    }),
  ],
};
