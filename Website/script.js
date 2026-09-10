(function() {
    const form = document.getElementById('myForm');
    const nameInput = document.getElementById('Name');
    const passInput = document.getElementById('Password');

    // НАСТРОЙКИ ВАЛИДАЦИИ
    const CONFIG = {
        loginMin: 4,      // минимальная длина логина
        loginMax: 16,     // максимальная длина логина
        passwordMin: 8,   // минимальная длина пароля
        passwordMax: 24   // максимальная длина пароля
    };

    // === ВАЛИДАЦИЯ ДЛЯ РЕГИСТРАЦИИ ===
    function validateRegistration() {
        const name = nameInput.value.trim();
        const password = passInput.value;

        // === ПРОВЕРКА ЛОГИНА ===
        const nameRegex = /^[A-Za-z0-9@_.-]+$/;
        if (!nameRegex.test(name)) {
            alert('Ошибка: Логин должен содержать только латинские буквы и цифры.');
            return false;
        }
        if (name.length < CONFIG.loginMin || name.length > CONFIG.loginMax) {
            alert(`Ошибка: Длина логина должна быть от ${CONFIG.loginMin} до ${CONFIG.loginMax} символов.`);
            return false;
        }

        // === ПРОВЕРКА ПАРОЛЯ ===
        // 1. Разрешённые символы
        const passRegex = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]+$/;
        if (!passRegex.test(password)) {
            alert('Ошибка: Пароль содержит недопустимые символы.\nРазрешены: латиница, цифры и спецсимволы: ! @ # $ % ^ & * ( ) _ + - = [ ] { } ; : \' " , . < > ? / \\ | ` ~');
            return false;
        }

        // 2. Проверка длины
        if (password.length < CONFIG.passwordMin || password.length > CONFIG.passwordMax) {
            alert(`Ошибка: Длина пароля должна быть от ${CONFIG.passwordMin} до ${CONFIG.passwordMax} символов.`);
            return false;
        }

        // 3. Проверка наличия заглавной буквы
        if (!/[A-Z]/.test(password)) {
            alert('Ошибка: Пароль должен содержать хотя бы одну заглавную букву (A-Z).');
            return false;
        }

        // 4. Проверка наличия строчной буквы
        if (!/[a-z]/.test(password)) {
            alert('Ошибка: Пароль должен содержать хотя бы одну строчную букву (a-z).');
            return false;
        }

        // 5. Проверка наличия цифры
        if (!/[0-9]/.test(password)) {
            alert('Ошибка: Пароль должен содержать хотя бы одну цифру (0-9).');
            return false;
        }

        // 6. Проверка наличия спецсимвола
        if (!/[!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]/.test(password)) {
            alert('Ошибка: Пароль должен содержать хотя бы один спецсимвол из списка:\n! @ # $ % ^ & * ( ) _ + - = [ ] { } ; : \' " , . < > ? / \\ | ` ~');
            return false;
        }

        return true;
    }

    // === ВАЛИДАЦИЯ ДЛЯ ВХОДА ===
    function validateLogin() {
        const name = nameInput.value.trim();
        const password = passInput.value;

        // Проверка: логин не пустой
        if (name.length === 0) {
            alert('Ошибка: Введите логин.');
            return false;
        }

        // Проверка: пароль не пустой
        if (password.length === 0) {
            alert('Ошибка: Введите пароль.');
            return false;
        }

        // Проверка длины логина
        if (name.length < CONFIG.loginMin || name.length > CONFIG.loginMax) {
            alert(`Ошибка: Длина логина должна быть от ${CONFIG.loginMin} до ${CONFIG.loginMax} символов.`);
            return false;
        }

        // Проверка длины пароля
        if (password.length < CONFIG.passwordMin || password.length > CONFIG.passwordMax) {
            alert(`Ошибка: Длина пароля должна быть от ${CONFIG.passwordMin} до ${CONFIG.passwordMax} символов.`);
            return false;
        }

        return true;
    }

    // ФУНКЦИЯ ОТПРАВКИ ЗАПРОСА НА СЕРВЕР
    function sendRequest(endpoint, login, password) {
        console.log('Отправка на сервер:', endpoint);

        const data = {
            login: login,
            password: password
        };

        fetch(`http://localhost:8080${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        })
        .then(response => response.text())
        .then(result => {
            alert('Ответ сервера: ' + result);
        })
        .catch(error => {
            alert('Ошибка соединения с сервером! Убедитесь, что сервер запущен на порту 8080.');
            console.error('Ошибка:', error);
        });
    }

    // ОБРАБОТЧИК КНОПКИ "ВОЙТИ"
    form.addEventListener('submit', function(e) {
        e.preventDefault();

        if (validateLogin()) {
            const name = nameInput.value.trim();
            const password = passInput.value;
            alert('Данные корректны! (отправка на /login)');
            sendRequest('/login', name, password);
        }
    });

    // ОБРАБОТЧИК КНОПКИ "ЗАРЕГИСТРИРОВАТЬСЯ"
    document.getElementById('registerBtn').addEventListener('click', function() {
        if (validateRegistration()) {
            const name = nameInput.value.trim();
            const password = passInput.value;
            alert('Данные корректны! (отправка на /register)');
            sendRequest('/register', name, password);
        }
    });
})();