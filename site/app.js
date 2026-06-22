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

  function go(n) {
    i = (n + count) % count;
    slides.style.transform = "translateX(" + (-i * 100) + "%)";
    for (var k = 0; k < dots.length; k++) dots[k].classList.toggle("active", k === i);
  }
  function next() { go(i + 1); }
  function prev() { go(i - 1); }
  function restart() { if (timer) clearInterval(timer); timer = setInterval(next, 6000); }

  carousel.querySelector(".next").addEventListener("click", function () { next(); restart(); });
  carousel.querySelector(".prev").addEventListener("click", function () { prev(); restart(); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "ArrowRight") { next(); restart(); }
    else if (e.key === "ArrowLeft") { prev(); restart(); }
  });
  go(0);
  restart();
})();
