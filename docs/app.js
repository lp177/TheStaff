// TheStaff site — carousel, copy-to-clipboard, repo links.

// 1) Repo links — replace with your GitHub repo URL after publishing.
var REPO = "https://github.com/your-org/thestaff";
document.querySelectorAll("[data-repo]").forEach(function (a) { a.href = REPO; });

// 2) Copy buttons — copy the command inside the same .codeblock
document.querySelectorAll(".copy-btn").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var code = btn.parentElement.querySelector("code");
    var text = code ? code.innerText : "";
    navigator.clipboard.writeText(text).then(function () {
      var prev = btn.textContent;
      btn.textContent = "Copied!";
      btn.classList.add("ok");
      setTimeout(function () { btn.textContent = prev; btn.classList.remove("ok"); }, 1400);
    }).catch(function () {});
  });
});

// 3) Carousel
(function () {
  var carousel = document.querySelector(".carousel");
  if (!carousel) return;
  var slides = carousel.querySelector(".slides");
  var count = slides.children.length;
  var dotsWrap = carousel.querySelector(".dots");
  var i = 0, timer = null;

  for (var d = 0; d < count; d++) {
    var b = document.createElement("button");
    b.setAttribute("aria-label", "Go to slide " + (d + 1));
    (function (idx) { b.addEventListener("click", function () { go(idx); restart(); }); })(d);
    dotsWrap.appendChild(b);
  }
  var dots = dotsWrap.children;

  // ---- fullscreen lightbox ----
  var lb = document.querySelector(".lightbox");
  var lbImg = lb && lb.querySelector(".lb-img");
  var lbCap = lb && lb.querySelector(".lb-cap");
  var lbOpen = false;

  function curFig() { return slides.children[i]; }
  function syncLB() {
    if (!lbOpen) return;
    var img = curFig().querySelector("img");
    var cap = curFig().querySelector("figcaption");
    lbImg.src = img.currentSrc || img.src;
    lbImg.alt = img.alt || "";
    lbCap.textContent = cap ? cap.textContent.trim() : "";
  }
  function openLB() {
    if (!lb || lbOpen) return;
    lbOpen = true;
    lb.hidden = false;
    lb.setAttribute("aria-hidden", "false");
    if (timer) { clearInterval(timer); timer = null; }
    syncLB();
    if (lb.requestFullscreen) lb.requestFullscreen().catch(function () {});
  }
  function closeLB() {
    if (!lbOpen) return;
    lbOpen = false;
    lb.hidden = true;
    lb.setAttribute("aria-hidden", "true");
    if (document.fullscreenElement) document.exitFullscreen().catch(function () {});
    restart();
  }

  function go(n) {
    i = (n + count) % count;
    slides.style.transform = "translateX(" + (-i * 100) + "%)";
    for (var k = 0; k < dots.length; k++) dots[k].classList.toggle("active", k === i);
    syncLB();
  }
  function next() { go(i + 1); }
  function prev() { go(i - 1); }
  function restart() { if (lbOpen) return; if (timer) clearInterval(timer); timer = setInterval(next, 6000); }

  carousel.querySelector(".next").addEventListener("click", function () { next(); restart(); });
  carousel.querySelector(".prev").addEventListener("click", function () { prev(); restart(); });
  carousel.querySelector(".fs").addEventListener("click", openLB);
  // clicking a slide image opens THAT image fullscreen
  Array.prototype.forEach.call(slides.children, function (fig, idx) {
    var img = fig.querySelector("img");
    if (img) img.addEventListener("click", function () { go(idx); openLB(); });
  });
  if (lb) {
    lb.querySelector(".lb-close").addEventListener("click", closeLB);
    lb.querySelector(".lb-prev").addEventListener("click", function (e) { e.stopPropagation(); prev(); });
    lb.querySelector(".lb-next").addEventListener("click", function (e) { e.stopPropagation(); next(); });
    lb.addEventListener("click", function (e) { if (e.target === lb) closeLB(); }); // click backdrop
    // Esc that exits OS fullscreen should also close the lightbox.
    document.addEventListener("fullscreenchange", function () {
      if (!document.fullscreenElement && lbOpen) closeLB();
    });
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { if (lbOpen) closeLB(); return; }
    if (e.key === "ArrowRight") { next(); restart(); }
    else if (e.key === "ArrowLeft") { prev(); restart(); }
  });
  go(0);
  restart();
})();
