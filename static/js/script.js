const fetchCurrentMode = async () => {
    try {
        const modeResponse = await fetch("/get-security-mode");
        const modeData = await modeResponse.json();

        const loginResponse = await fetch("/get-login-status");
        const loginData = await loginResponse.json();

        const modeStatus = document.getElementById("mode-status");
        const privilegedDescription = document.getElementById("privileged-description");
        const directObjectDescription = document.getElementById("direct-object-description");
        const apiDeleteDescription = document.getElementById("api-delete-description");
        const fileAccessDescription = document.getElementById("file-access-description");
        const massAssignmentDescription = document.getElementById("mass-assignment-description");
        const idorDescription = document.getElementById("idor-description");

        // Set mode status text
        const mode = modeData.is_secure ? "Secure" : "Insecure";
        modeStatus.textContent = `Current Mode: ${mode}`;

        // Check if the user is logged in
        const userLoggedIn = loginData.logged_in;

        // Update descriptions for each example
        if (privilegedDescription) {
            privilegedDescription.textContent = userLoggedIn
                ? modeData.is_secure
                    ? "In secure mode, access is restricted to authorized roles only. Unauthorized users are redirected or blocked."
                    : "In insecure mode, users can access this area without proper authorization."
                : "You must log in to access this feature.";
        }

        if (directObjectDescription) {
            directObjectDescription.textContent = userLoggedIn
                ? modeData.is_secure
                    ? "In secure mode, all object references are validated, ensuring users cannot access resources they shouldn't. Clicking this link will take you do Bob's public file at /direct-object-reference/2. You can try to access Alice's private file at /direct-object-reference/1, but will be blocked."
                    : "In insecure mode, manipulating object identifiers allows unauthorized access to resources. Clicking this link will take you do Bob's public file at /direct-object-reference/2. You can switch this to Alice's private file at /direct-object-reference/1 and access it without issue."
                : "You must log in to access this feature.";
        }

        if (apiDeleteDescription) {
            apiDeleteDescription.textContent = userLoggedIn
                ? modeData.is_secure  
                    ? "In secure mode, deletion is restricted to the file owner, and protected files cannot be deleted.To test this, use a tool like Postman or cURL to send a `POST` request to `/api-delete/<file_name>` and delete any file that you own, then try one that you do not own. "
                    : "In insecure mode, use a tool like Postman or cURL to send a `POST` request to `/api-delete/<file_name>` and delete any file, even if you don't own it. "
                : "You must log in to access this feature.";
        }

        if (fileAccessDescription) {
            fileAccessDescription.textContent = userLoggedIn
                ? modeData.is_secure
                    ? "In secure mode, file paths are validated to prevent unauthorized access. To test this, try to access a file that is public, and compare that to a request for a file that is owned by another user. To test this, use a file query parameter (e.g. /direct-file-access?file=public_file_1.txt) and try to access a file below. "
                    : "In insecure mode, file paths are not validated, allowing potential data exposure. To test this, try accessing any of the files listed, even if you do not own it.  To test this, use a file query parameter (e.g. /direct-file-access?file=public_file_1.txt) and try to access a file below."
                : "You must log in to access this feature.";
        }

        if (massAssignmentDescription) {
            massAssignmentDescription.textContent = userLoggedIn
                ? modeData.is_secure
                    ? "In secure mode, only specific fields are allowed to be updated."
                    : "In insecure mode, all fields can be updated, introducing vulnerabilities."
                : "You must log in to access this feature.";
        }

        if (idorDescription) {
            idorDescription.textContent = userLoggedIn
                ? modeData.is_secure
                    ? "In secure mode, logging in as another user is prevented."
                    : "In insecure mode, it is possible to log in as another user by manipulating IDs."
                : "You must log in to access this feature.";
        }
    } catch (error) {
        console.error("Error fetching current mode or login status:", error);
    }
};

const toggleMode = async () => {
    try {
        await fetch("/toggle-security", { method: "POST" });
        fetchCurrentMode(); // Refresh the mode display after toggling
    } catch (error) {
        console.error("Error toggling mode:", error);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    const currentModeElement = document.getElementById('current-mode');
    const currentMode = currentModeElement.textContent.trim();
    console.log(`Current Mode: ${currentMode}`);
});

document.addEventListener("DOMContentLoaded", () => {
    fetchCurrentMode(); // Sync the UI with the server state on load
    const toggleButton = document.getElementById("toggle-mode");
    if (toggleButton) {
        toggleButton.addEventListener("click", toggleMode);
    }
});

document.getElementById('update-profile').addEventListener('click', async () => {
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const role = document.getElementById('role').value;
    const responseMessage = document.getElementById('update-response');
    const modeDisplay = document.getElementById('mode'); // Mode display element

    try {
        const response = await fetch('/mass-assignment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, role })
        });

        if (!response.ok) {
            responseMessage.textContent = 'Error updating profile.';
            return;
        }

        const result = await response.json();
        responseMessage.textContent = result.message || 'Profile updated successfully.';

        // Update the mode display
        modeDisplay.textContent = `Current Mode: ${result.mode}`;

        // Update the profile dynamically
        if (result.updatedFields) {
            if (result.updatedFields.username) {
                document.getElementById('current-username').textContent = result.updatedFields.username;
            }
            if (result.updatedFields.email) {
                document.getElementById('current-email').textContent = result.updatedFields.email;
            }
            if (result.updatedFields.role) {
                document.getElementById('current-role').textContent = result.updatedFields.role;
            }
        }
    } catch (error) {
        responseMessage.textContent = 'Error connecting to the server.';
    }
});

document.addEventListener("DOMContentLoaded", async () => {
    const updateProfileButton = document.getElementById('update-profile');
    const responseMessage = document.getElementById('update-response');
    const currentUsername = document.getElementById('current-username');
    const currentEmail = document.getElementById('current-email');
    const currentRole = document.getElementById('current-role');

    updateProfileButton.addEventListener('click', async () => {
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const role = document.getElementById('role').value;

        try {
            const response = await fetch('/mass-assignment', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, role })
            });

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            const result = await response.json();

            // Display response message
            responseMessage.textContent = result.message;

            // Dynamically update profile fields
            if (result.updatedFields) {
                if (result.updatedFields.username) {
                    currentUsername.textContent = result.updatedFields.username;
                }
                if (result.updatedFields.email) {
                    currentEmail.textContent = result.updatedFields.email;
                }
                if (result.updatedFields.role) {
                    currentRole.textContent = result.updatedFields.role;
                }
            }
        } catch (error) {
            console.error('Error updating profile:', error);
            responseMessage.textContent = 'Error connecting to the server.';
        }
    });
});
