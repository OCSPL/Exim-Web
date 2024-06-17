// Assuming you have a JavaScript function to handle form submission

function submitForm() {
    // Construct the form data object
    var formData = {
        // Include other form fields here if needed
        conditions: [
            {
                form: {
                    column: 'SB_NO',
                    condition: 'contains',
                    value: document.getElementById('sb_no_input').value
                }
            },
            {
                form: {
                    column: 'SB_DATE',
                    condition: 'contains',
                    value: document.getElementById('sb_date_input').value
                }
            },
            // Add other conditions for export data here
        ]
    };

    // Convert formData to JSON string
    var jsonData = JSON.stringify(formData);

    // Make AJAX request to the server
    // Example using jQuery AJAX
    $.ajax({
        type: 'POST',
        url: '/download_results/export',  // Adjust the URL as needed
        contentType: 'application/json',
        data: jsonData,
        success: function(response) {
            // Handle success response
        },
        error: function(xhr, status, error) {
            // Handle error response
        }
    });
}
