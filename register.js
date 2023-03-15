const fn = (event) => {
$(document).ready(function () {
    $("form").submit(function (event) {
        var formData = {
            name: $("#name").val(),
            email: $("#email").val(),
            password1: $("#password1").val(),
            password2: $("#password2").val(),
        };

        localStorage.setItem('name', $("#name").val() )


        $.ajax({
            type: "POST",
            url: "register_handler.php",
            data: formData,
            dataType: "json",
            encode: true,
        }).done(function (data) {
            console.log(data);
        });

        event.preventDefault();
    });
});