(function () {
  "use strict";
  const chips = document.querySelectorAll("#cat-chips button");
  chips.forEach((b) => b.addEventListener("click", () => {
    chips.forEach((x) => x.classList.toggle("on", x === b));
    const cat = b.dataset.cat;
    document.querySelectorAll(".story-wrap").forEach((s) => { s.hidden = cat !== "" && s.dataset.cat !== cat; });
  }));
})();
