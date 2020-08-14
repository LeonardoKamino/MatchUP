function isNumberKey(evt){
  var charCode = (evt.which) ? evt.which : evt.keyCode
  if (charCode > 31 && (charCode < 48 || charCode > 57))
      return false;
  return true;
}

let input = document.querySelector('input[name=username]');
input.onkeyup = function() {
     $.get('/check?q=' + input.value, function(data) {
         if (data.response === "False"){
            document.getElementById('submit_btn').disabled = true;
            document.getElementById("alert").innerHTML = "Username is not available!";
         }
         else {
            document.getElementById('submit_btn').disabled = false;
            document.getElementById("alert").innerHTML = "";
         }
     });
 };

 function confirm() {
    return confirm('Are you sure you want to delete this post?');
}