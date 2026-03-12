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

function setGoogleTranslateCookie(lang) {
  var value = lang === "ja" ? "/auto/ja" : "/ja/" + lang;
  var cookie = "googtrans=" + value + ";path=/";
  document.cookie = cookie;
  document.cookie = cookie + ";domain=" + location.hostname;
}

function setLanguage(lang) {
  localStorage.setItem("pawnyable-lang", lang);
  setGoogleTranslateCookie(lang);
  location.reload();
}

function updateLanguageButtons() {
  var lang = localStorage.getItem("pawnyable-lang") || "ja";
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
