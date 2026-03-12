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

function setLanguage(lang) {
  localStorage.setItem("pawnyable-lang", lang);
  applyLanguage(lang);
}

function applyLanguage(lang) {
  var supported = ["ja", "ko", "en"];
  if (supported.indexOf(lang) === -1) {
    lang = "ja";
  }

  var i18nNodes = document.querySelectorAll(".i18n");
  for (var i = 0; i < i18nNodes.length; i++) {
    var text = i18nNodes[i].getAttribute("data-" + lang);
    if (text) {
      i18nNodes[i].innerHTML = text;
    }
  }

  var buttons = document.querySelectorAll(".lang-btn");
  for (var j = 0; j < buttons.length; j++) {
    if (buttons[j].getAttribute("data-lang") === lang) {
      buttons[j].classList.add("active");
    } else {
      buttons[j].classList.remove("active");
    }
  }
}

function detectors() {
  detectTaskList();
  detectBlockTable();
  var lang = localStorage.getItem("pawnyable-lang") || "ja";
  applyLanguage(lang);
}
