function detectTaskList() {
  var taskListObjects = document.getElementsByTagName("input");
  for (var i = 0; i < taskListObjects.length; i++) {
    var par = taskListObjects[i].parentNode;
    par.classList.add("task-list-item");
    par.parentNode.classList.add("task-list");
  }
}

function detectBlockTable() {
  var tableListObjects = document.getElementsByTagName("thead");
  for (var i = 0; i < tableListObjects.length; i++) {
    var par = tableListObjects[i].parentNode;
    par.classList.add("block-table");
  }
}

function toggleMenu() {
  var menuList = document.getElementsByClassName("menu-list")[0];
  var menuButton = document.getElementById("menu-btn");
  if (menuList.classList.contains("active")) {
    menuList.classList.remove("active");
    menuButton.innerHTML = "MENU";
  } else {
    menuList.classList.add("active");
    menuButton.innerHTML = '<div class="icon arrow-up"> </div>';
  }
}

function currentLanguageFromPath() {
  var path = window.location.pathname;
  if (path.indexOf("/ko/") === 0) return "ko";
  if (path.indexOf("/en/") === 0) return "en";
  return "ja";
}

function pathForLanguage(lang) {
  var path = window.location.pathname;
  var search = window.location.search || "";
  var hash = window.location.hash || "";
  if (path.indexOf("/ko/") === 0) path = path.slice(3);
  if (path.indexOf("/en/") === 0) path = path.slice(3);

  if (lang === "ja") {
    return path + search + hash;
  }
  return "/" + lang + path + search + hash;
}

function setLanguage(lang) {
  window.location.href = pathForLanguage(lang);
}

function updateLanguageButtons() {
  var lang = currentLanguageFromPath();
  var buttons = document.querySelectorAll(".lang-btn");
  for (var i = 0; i < buttons.length; i++) {
    if (buttons[i].getAttribute("data-lang") === lang) {
      buttons[i].classList.add("active");
    } else {
      buttons[i].classList.remove("active");
    }
  }
}

function detectors() {
  detectTaskList();
  detectBlockTable();
  updateLanguageButtons();
}
