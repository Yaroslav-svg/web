
// ========================================
// SECUREAUTH — ГОЛОВНИЙ JAVASCRIPT
// ========================================

const STORAGE_KEY = "secureauth_users";
const CRYPTO_KEY = "secureauth_crypto_key";
const SESSION_KEY = "secureauth_session";

// ========================================
// РОБОТА З AES-GCM
// ========================================

function toBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

function fromBase64(base64) {
    const binary = atob(base64);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

// Створення або отримання ключа
async function getEncryptionKey() {
    let storedKey = localStorage.getItem(CRYPTO_KEY);

    if (!storedKey) {
        const key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        const rawKey = await crypto.subtle.exportKey(
            "raw",
            key
        );

        storedKey = toBase64(rawKey);

        localStorage.setItem(CRYPTO_KEY, storedKey);
    }

    const rawKey = fromBase64(storedKey);

    return crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

// Шифрування інформації
async function encryptData(data) {
    const key = await getEncryptionKey();

    const iv = crypto.getRandomValues(
        new Uint8Array(12)
    );

    const encodedData = new TextEncoder().encode(
        JSON.stringify(data)
    );

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encodedData
    );

    return {
        iv: toBase64(iv),
        data: toBase64(encrypted)
    };
}

// Дешифрування інформації
async function decryptData(encryptedData) {
    const key = await getEncryptionKey();

    const iv = fromBase64(encryptedData.iv);
    const data = fromBase64(encryptedData.data);

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        data
    );

    const decoded = new TextDecoder().decode(decrypted);

    return JSON.parse(decoded);
}

// ========================================
// ХЕШУВАННЯ ПАРОЛЯ
// ========================================

async function hashPassword(password, salt) {
    const encoder = new TextEncoder();

    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: encoder.encode(salt),
            iterations: 100000,
            hash: "SHA-256"
        },
        passwordKey,
        256
    );

    return toBase64(derivedBits);
}

// ========================================
// РОБОТА З КОРИСТУВАЧАМИ
// ========================================

function getUsers() {
    return JSON.parse(
        localStorage.getItem(STORAGE_KEY) || "[]"
    );
}

function saveUsers(users) {
    localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(users)
    );
}

// ========================================
// СТОРІНКА АВТОРИЗАЦІЇ
// ========================================

const loginTab = document.querySelector("#loginTab");
const registerTab = document.querySelector("#registerTab");

const loginForm = document.querySelector("#loginForm");
const registerForm = document.querySelector("#registerForm");

const message = document.querySelector("#message");

function showMessage(text, success = false) {
    if (!message) return;

    message.textContent = text;
    message.className = success
        ? "message success"
        : "message";
}

if (loginTab && registerTab) {

    loginTab.addEventListener("click", () => {
        loginTab.classList.add("active");
        registerTab.classList.remove("active");

        loginForm.classList.remove("hidden");
        registerForm.classList.add("hidden");

        showMessage("");
    });

    registerTab.addEventListener("click", () => {
        registerTab.classList.add("active");
        loginTab.classList.remove("active");

        registerForm.classList.remove("hidden");
        loginForm.classList.add("hidden");

        showMessage("");
    });

    // ====================================
    // РЕЄСТРАЦІЯ
    // ====================================

    registerForm.addEventListener("submit", async event => {
        event.preventDefault();

        try {
            const name = document.querySelector(
                "#regName"
            ).value.trim();

            const surname = document.querySelector(
                "#regSurname"
            ).value.trim();

            const email = document.querySelector(
                "#regEmail"
            ).value.trim().toLowerCase();

            const password = document.querySelector(
                "#regPassword"
            ).value;

            if (!name || !surname || !email || !password) {
                return showMessage(
                    "Заповніть усі поля."
                );
            }

            if (password.length < 8) {
                return showMessage(
                    "Пароль повинен містити мінімум 8 символів."
                );
            }

            const users = getUsers();

            // Перевірка унікальності email
            for (const user of users) {
                const decrypted = await decryptData(user);

                if (decrypted.email === email) {
                    return showMessage(
                        "Користувач з таким email вже існує."
                    );
                }
            }

            const salt = toBase64(
                crypto.getRandomValues(new Uint8Array(16))
            );

            const passwordHash = await hashPassword(
                password,
                salt
            );

            const userData = {
                name,
                surname,
                email,
                salt,
                passwordHash,
                registrationDate: new Date().toLocaleString(
                    "uk-UA"
                )
            };

            const encryptedUser = await encryptData(
                userData
            );

            users.push(encryptedUser);

            saveUsers(users);

            showMessage(
                "Реєстрація успішна! Тепер можете увійти.",
                true
            );

            registerForm.reset();

            loginTab.click();

        } catch (error) {
            console.error(error);

            showMessage(
                "Помилка під час реєстрації."
            );
        }
    });

    // ====================================
    // АВТОРИЗАЦІЯ КОРИСТУВАЧА
    // ====================================

    loginForm.addEventListener("submit", async event => {
        event.preventDefault();

        try {
            const email = document.querySelector(
                "#loginEmail"
            ).value.trim().toLowerCase();

            const password = document.querySelector(
                "#loginPassword"
            ).value;

            const users = getUsers();

            for (const encryptedUser of users) {
                const user = await decryptData(
                    encryptedUser
                );

                if (user.email === email) {
                    const enteredHash = await hashPassword(
                        password,
                        user.salt
                    );

                    if (enteredHash === user.passwordHash) {
                        sessionStorage.setItem(
                            SESSION_KEY,
                            JSON.stringify({
                                email: user.email,
                                role: "user"
                            })
                        );

                        window.location.href = "user.html";
                        return;
                    }

                    break;
                }
            }

            showMessage(
                "Неправильна електронна пошта або пароль."
            );

        } catch (error) {
            console.error(error);

            showMessage(
                "Не вдалося виконати авторизацію."
            );
        }
    });

    // ====================================
    // ВХІД АДМІНІСТРАТОРА
    // ====================================

    document.querySelector(
        "#adminLoginButton"
    ).addEventListener("click", async () => {

        const username = prompt(
            "Введіть логін адміністратора:"
        );

        if (username === null) return;

        const password = prompt(
            "Введіть пароль адміністратора:"
        );

        if (password === null) return;

        try {
            const response = await fetch(
                "/api/admin/login",
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        username,
                        password
                    })
                }
            );

            const result = await response.json();

            if (!response.ok) {
                return showMessage(result.message);
            }

            sessionStorage.setItem(
                "adminToken",
                result.token
            );

            window.location.href = "admin.html";

        } catch (error) {
            showMessage(
                "Не вдалося підключитися до сервера."
            );
        }
    });
}

// ========================================
// АДМІНІСТРАТИВНА ПАНЕЛЬ
// ========================================

const usersTable = document.querySelector(
    "#usersTable"
);

if (usersTable) {

    async function loadAdminPanel() {
        const token = sessionStorage.getItem(
            "adminToken"
        );

        if (!token) {
            window.location.href = "index.html";
            return;
        }

        try {
            const response = await fetch(
                "/api/admin/check",
                {
                    headers: {
                        Authorization: `Bearer ${token}`
                    }
                }
            );

            if (!response.ok) {
                sessionStorage.removeItem("adminToken");
                window.location.href = "index.html";
                return;
            }

            await loadUsers();

        } catch {
            document.querySelector(
                "#adminMessage"
            ).textContent = "Помилка підключення до сервера.";
        }
    }

    async function loadUsers() {
        const users = getUsers();

        usersTable.innerHTML = "";

        let count = 0;

        for (const encryptedUser of users) {
            try {
                const user = await decryptData(
                    encryptedUser
                );

                count++;

                const row = document.createElement("tr");

                const values = [
                    count,
                    user.name,
                    user.surname,
                    user.email,
                    user.registrationDate
                ];

                values.forEach(value => {
                    const cell = document.createElement("td");

                    cell.textContent = value;

                    row.appendChild(cell);
                });

                usersTable.appendChild(row);

            } catch (error) {
                console.error(
                    "Не вдалося розшифрувати запис:",
                    error
                );
            }
        }

        document.querySelector(
            "#userCount"
        ).textContent = count;

        if (count === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.textContent = "Користувачів поки немає.";

            row.appendChild(cell);
            usersTable.appendChild(row);
        }
    }

    document.querySelector(
        "#refreshUsers"
    ).addEventListener("click", loadUsers);

    loadAdminPanel();
}

// ========================================
// ОСОБИСТИЙ КАБІНЕТ
// ========================================

const welcomeName = document.querySelector(
    "#welcomeName"
);

if (welcomeName) {

    async function loadUserPage() {
        const session = JSON.parse(
            sessionStorage.getItem(SESSION_KEY) || "null"
        );

        if (!session || session.role !== "user") {
            window.location.href = "index.html";
            return;
        }

        try {
            const users = getUsers();

            for (const encryptedUser of users) {
                const user = await decryptData(
                    encryptedUser
                );

                if (user.email === session.email) {
                    welcomeName.textContent = user.name;

                    document.querySelector(
                        "#userEmail"
                    ).textContent = user.email;

                    return;
                }
            }

            sessionStorage.removeItem(SESSION_KEY);

            window.location.href = "index.html";

        } catch (error) {
            console.error(error);
        }
    }

    loadUserPage();
}

// ========================================
// ВИХІД ІЗ СИСТЕМИ
// ========================================

const logoutButton = document.querySelector(
    "#logoutButton"
);

if (logoutButton) {
    logoutButton.addEventListener("click", () => {
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem("adminToken");

        window.location.href = "index.html";
    });
}
