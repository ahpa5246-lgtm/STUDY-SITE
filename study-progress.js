/* Small, dependency-free study location store. Completion status is separate. */
(function(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.StudyProgress = api;
})(typeof window !== "undefined" ? window : null, function() {
  "use strict";
  const KEY = "control-lecture-two-position-v1";

  function restore(storage, lessons) {
    const empty = { index: 0, step: 0, resumed: false };
    if (!storage || !Array.isArray(lessons) || !lessons.length) return empty;
    try {
      const saved = JSON.parse(storage.getItem(KEY) || "null");
      if (!saved || saved.version !== 1 || typeof saved.lessonId !== "string"
          || !Number.isSafeInteger(saved.step) || saved.step < 0) return empty;
      const index = lessons.findIndex(lesson => lesson.id === saved.lessonId);
      if (index === -1) return empty;
      const steps = lessons[index].steps;
      if (!Array.isArray(steps) || !steps.length) return empty;
      return { index, step: Math.min(saved.step, steps.length - 1), resumed: true };
    } catch (_) {
      // Private mode, blocked storage and malformed data must not break lessons.
      return empty;
    }
  }

  function save(storage, lessonId, step) {
    if (!storage || typeof lessonId !== "string" ||
        !Number.isSafeInteger(step) || step < 0) return false;
    try {
      storage.setItem(KEY, JSON.stringify({ version: 1, lessonId, step }));
      return true;
    } catch (_) {
      return false;
    }
  }

  return Object.freeze({ KEY, restore, save });
});
