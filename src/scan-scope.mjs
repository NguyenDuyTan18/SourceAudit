export const MIB = 1024 * 1024;
export const MAX_SOURCE_FILE_BYTES = 10 * MIB;
export const MAX_SOURCE_TOTAL_BYTES = 50 * MIB;
export const MAX_ZIP_BYTES = 50 * MIB;
export const MAX_SOURCE_FILES = 2000;

const TEST_DIRECTORIES = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'e2e', 'testdata', 'test-data', 'cypress', 'playwright']);

export function isDockerfileName(name) {
  return /^(?:Dockerfile(?:\.[\w-]+)*|[\w.\-]+\.Dockerfile)$/i.test(name) && !/\.dockerignore$/i.test(name);
}

// Pass paths relative to the scan root, with '/' separators and a trailing '/' for directories.
export function isTestPath(file) {
  const parts = file.toLowerCase().split('/');
  const name = parts.pop();
  return parts.some((part) => TEST_DIRECTORIES.has(part)) ||
    /\.(?:test|spec|e2e)\.[a-z0-9]+$|^test_.+\.py$|_test\.(?:py|go|rb)$|_spec\.rb$|tests?\.(?:java|cs|kt)$/.test(name);
}
