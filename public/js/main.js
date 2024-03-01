document.addEventListener('DOMContentLoaded', () => {
    document.querySelector(".user-list").addEventListener("click", async (e) => {
        let target = e.target;
        if (target.classList.contains("delete")) {
            const username = target.getAttribute('data-username');
            console.log(username);
            if (!username) return;

            try {
                const response = await fetch(`/user/${username}`, { method: 'DELETE' });
                if (response.ok) {
                    target.parentElement.parentElement.remove();
                    showAlert("User deleted successfully", "success");
                } else {
                    showAlert("Failed to delete user", "danger");
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert("An error occurred", "danger");
            }
        } else if (target.classList.contains("edit")) {
            const username = target.getAttribute('data-username');
            console.log("Edit username:", username);
            if (!username) return;

            openEditFormOrModal(username);
        }
    });

    function openEditFormOrModal(username) {
        const modal = new bootstrap.Modal(document.getElementById('editModal'));
        modal.show();

        const usernameInput = document.getElementById('editUsername');
        const roleInput = document.getElementById('editRole');

        // Prefill the usernameInput and roleInput if necessary
        // usernameInput.value = username;
        // roleInput.value = ''; // Set this based on your application's needs

        const editForm = document.getElementById('editForm');
        editForm.addEventListener('submit', async (e) => {
            e.preventDefault();
        
            const updatedUsername = usernameInput.value;
            const updatedRole = roleInput.value;
        
            try {
                // Construct the correct URL using the username variable
                const url = `/user/${username}`; // Ensure this username variable is the original username of the user being edited
        
                const response = await fetch(url, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ newUsername: updatedUsername, newRole: updatedRole })
                });
                if (response.ok) {
                    modal.hide();
                    showAlert("User data edited successfully", "success");
                } else {
                    showAlert("Failed to edit user", "danger");
                }
            } catch (error) {
                console.error('Error:', error);
                showAlert("An error occurred", "danger");
            }
        });
        
    }

    function showAlert(message, className) {
        const div = document.createElement("div");
        div.className = `alert alert-${className}`;
        div.appendChild(document.createTextNode(message));
        const container = document.querySelector(".container") || document.body;
        const firstChild = container.firstChild;
        container.insertBefore(div, firstChild);
        setTimeout(() => div.remove(), 5000); // Adjust timeout as needed
    }

    async function fetchFacts() {
        try {
            const response = await fetch('https://cat-fact.herokuapp.com/facts');
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.json();
            displayFacts(data);
        } catch (error) {
            console.error('There has been a problem with your fetch operation:', error);
        }
    }
    function addRandomPhotosCarousels() {
        const photoCells = document.querySelectorAll('.user-list tr td:nth-child(4)');
        
        

        photoCells.forEach((cell, index) => {
            const carouselId = `carouselExample${index}`;
            const carouselHTML = `
                <div id="${carouselId}" class="carousel slide" data-ride="carousel">
                    <div class="carousel-inner">
                        <div class="carousel-item active">
                            <img src="https://picsum.photos/seed/${Math.random()}/100/100" class="d-block w-100" alt="Random Image">
                        </div>
                        <div class="carousel-item">
                            <img src="https://picsum.photos/seed/${Math.random()}/100/100" class="d-block w-100" alt="Random Image">
                        </div>
                        <div class="carousel-item">
                            <img src="https://picsum.photos/seed/${Math.random()}/100/100" class="d-block w-100" alt="Random Image">
                        </div>
                    </div>
                    <a class="carousel-control-prev" href="#${carouselId}" role="button" data-bs-slide="prev">
                        <span class="carousel-control-prev-icon" aria-hidden="true"></span>
                        <span class="visually-hidden">Previous</span>
                    </a>
                    <a class="carousel-control-next" href="#${carouselId}" role="button" data-bs-slide="next">
                        <span class="carousel-control-next-icon" aria-hidden="true"></span>
                        <span class="visually-hidden">Next</span>
                    </a>

                </div>
            `;

            // Empty the cell and append the carousel
            cell.innerHTML = carouselHTML;
        });
    }
    function shouldAddCarousels() {
        const fourthTdElements = document.querySelectorAll('.user-list tr td:nth-child(4)');
    
        // Check if any of these elements has an ID of 'photo'
        for (let i = 0; i < fourthTdElements.length; i++) {
            if (fourthTdElements[i].id === 'photo') {
                return true; // If found, return true
            }
        }
        return false; // If none found, return false
    }
    if (shouldAddCarousels()) {
        addRandomPhotosCarousels();
    }
    
});

function displayJoke(jokeData) {
    const jokesContainer = document.getElementById('jokes-container');
    jokesContainer.innerHTML = '';

    const jokeElement = document.createElement('p');
    jokeElement.textContent = jokeData;

    jokesContainer.appendChild(jokeElement);
}

async function getRandomJoke() {
    const options = {
        method: 'GET',
        url: 'https://matchilling-chuck-norris-jokes-v1.p.rapidapi.com/jokes/random',
        headers: {
            accept: 'application/json',
            'X-RapidAPI-Key': '29213011b5msh17845e76bb0fb12p1e4ba5jsnc473aadbd65d',
            'X-RapidAPI-Host': 'matchilling-chuck-norris-jokes-v1.p.rapidapi.com'
        }
    };

    try {
        const response = await axios.request(options);
        displayJoke(response.data.value);
    } catch (error) {
        console.error(error);
    }
}

function fun() {
    // Define the size of the image you want (e.g., 200x200 pixels)
    const width = 200;
    const height = 200;
    const url = `https://picsum.photos/${width}/${height}`;

    // Create an <img> element and set its source to the Picsum URL
    const image = new Image();
    image.src = url;
    image.alt = "A random image";
    image.className = "img-fluid"; 

    const container = document.getElementById('funFactInfo');

    container.innerHTML = ''; 
    container.appendChild(image);
}


async function fetchRandomAnimeGif() {
    const url = 'https://any-anime.p.rapidapi.com/v1/anime/gif/1';
    const options = {
        method: 'GET',
        headers: {
            'X-RapidAPI-Key': '29213011b5msh17845e76bb0fb12p1e4ba5jsnc473aadbd65d',
            'X-RapidAPI-Host': 'any-anime.p.rapidapi.com'
        }
    };

    try {
        const response = await fetch(url, options);
        const result = await response.json();
        const imageUrl = result.images[0];
        const animeGifContainer = document.getElementById('animeGifContainer');
        animeGifContainer.innerHTML = `<img src="${imageUrl}" alt="Anime GIF" class="img-fluid">`;
    } catch (error) {
        console.error('Error fetching random anime GIF:', error);
    }
}



