$(document).ready(function () {
    $("form").submit(function (event) {
        var formData = {
            age: $("#age").val(),
            dob: $("#dob").val(),
            contact: $("#contact").val(),
        };
        $.ajax({
            type: "POST",
            url: "profile_handler.php",
            data: formData,
            dataType: "json",
            encode: true,
        }).done(function (data) {
            console.log(data);
        });

        event.preventDefault();
    });
});