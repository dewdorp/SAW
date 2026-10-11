/* Runs only in browsers without ES module support (Internet Explorer 11, very old Edge): SAW needs Chrome or
   Chromium Edge. ES5 on purpose; loaded with <script nomodule>, so modern browsers never fetch it. */
(function () {
  var msg = "SAW는 Chrome 또는 Microsoft Edge(최신)에서만 동작합니다. " +
    "Internet Explorer에서는 화면이 열리지 않습니다. Chrome으로 같은 주소에 접속하세요.";
  function show() {
    var root = document.getElementById("root") || document.body;
    root.innerHTML = "";
    var p = document.createElement("p");
    p.appendChild(document.createTextNode(msg));
    p.style.font = "16px sans-serif";
    p.style.margin = "48px";
    root.appendChild(p);
  }
  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", show); } else { show(); }
})();
