'use strict';
// Progress for the fictional Northwind Security Basics course, kept in localStorage of the course origin.
window.NW = {
  load() {
    try {
      return Object.assign({ slides: [], quiz: false, inbox: false, module: false }, JSON.parse(localStorage.getItem('nw-progress') || '{}'));
    } catch {
      return { slides: [], quiz: false, inbox: false, module: false };
    }
  },
  save(p) {
    localStorage.setItem('nw-progress', JSON.stringify(p));
  },
  update(fn) {
    const p = this.load();
    fn(p);
    this.save(p);
    return p;
  },
  missing(p) {
    const m = [];
    for (const n of [1, 2, 3]) if (!p.slides.includes(n)) m.push(`Slide ${n}`);
    if (!p.quiz) m.push('Knowledge check quiz');
    if (!p.inbox) m.push('Spot-the-phish inbox');
    if (!p.module) m.push('Interactive module (course player)');
    return m;
  },
};
