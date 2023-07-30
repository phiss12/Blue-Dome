document.getElementById('file').addEventListener('change', function() {
    var fileList = document.getElementById('fileList');
    fileList.innerHTML = ""; // Clear the current list
    for (var i = 0; i < this.files.length; i++) {
        fileList.innerHTML += "<p>" + this.files[i].name + "</p>";
    }
});
