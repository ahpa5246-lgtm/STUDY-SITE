/* Run: node --test tests/study-progress.test.cjs */
const test = require("node:test");
const assert = require("node:assert/strict");
const { KEY, restore, save } = require("../study-progress.js");

const lessons = [
  { id: "ex21", steps: [{}, {}, {}] },
  { id: "hw5", steps: [{}, {}, {}, {}] },
];
function memory() {
  const items = new Map();
  return {
    getItem: key => items.get(key) ?? null,
    setItem: (key, value) => items.set(key, value),
  };
}

test("fresh visitor starts at the first lesson", () => {
  assert.deepEqual(restore(memory(), lessons),
    { index: 0, step: 0, resumed: false });
});

test("returning visitor resumes the saved lesson and solution step", () => {
  const storage = memory();
  assert.equal(save(storage, "hw5", 2), true);
  assert.deepEqual(restore(storage, lessons),
    { index: 1, step: 2, resumed: true });
});

test("reordered lesson list uses stable lesson ids rather than stale indexes", () => {
  const storage = memory();
  save(storage, "hw5", 1);
  assert.equal(restore(storage, lessons.slice().reverse()).index, 0);
});

test("revised handout clamps an old step to the final available step", () => {
  const storage = memory();
  storage.setItem(KEY, JSON.stringify({ version: 1, lessonId: "ex21", step: 99 }));
  assert.deepEqual(restore(storage, lessons),
    { index: 0, step: 2, resumed: true });
});

test("unknown lesson and corrupted state fail closed without exceptions", () => {
  const storage = memory();
  for (const value of ["{broken", JSON.stringify({version:1,lessonId:"missing",step:4}),
                       JSON.stringify({version:1,lessonId:"ex21",step:-2})]) {
    storage.setItem(KEY, value);
    assert.equal(restore(storage, lessons).resumed, false);
  }
});

test("disabled storage does not prevent studying", () => {
  const blocked = { getItem: () => { throw Error("denied"); },
                    setItem: () => { throw Error("denied"); } };
  assert.equal(restore(blocked, lessons).resumed, false);
  assert.equal(save(blocked, "ex21", 1), false);
  assert.equal(save(memory(), "ex21", -1), false);
});
