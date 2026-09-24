(function() {
    const form = document.getElementById('myForm');
    const nameInput = document.getElementById('Name');
    const passInput = document.getElementById('Password');

    // НАСТРОЙКИ ВАЛИДАЦИИ
    const CONFIG = {
        loginMin: 4,      // минимальная длина логина
        loginMax: 16,     // максимальная длина логина
        passwordMin: 8,   // минимальная длина пароля
        passwordMax: 128   // максимальная длина пароля
    };

    // === ГЕНЕРАЦИЯ СЛУЧАЙНОЙ СОЛИ ===
    // Возвращает 16 случайных байт в виде hex-строки (32 символа)
    function generateSalt() {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // === ХЕШИРОВАНИЕ ПАРОЛЯ ЧЕРЕЗ ARGON2ID ===
    // Возвращает hex-строку хеша (64 символа)
    async function hashPassword(password, salt) {
        const result = await argon2.hash({
            pass: password,
            salt: salt,
            time: 3,                        // 3 итерации
            mem: 4096,                      // 4 МБ памяти
            hashLen: 32,                    // 32 байта = 256 бит
            parallelism: 1,                 // 1 поток
            type: argon2.ArgonType.Argon2id // рекомендуемый вариант
        });
        return result.hashHex;
    }

    // === ВАЛИДАЦИЯ ДЛЯ РЕГИСТРАЦИИ ===
    function validateRegistration() {
        const name = nameInput.value.trim();
        const password = passInput.value;

        // === ПРОВЕРКА ЛОГИНА ===
        const nameRegex = /^[A-Za-z0-9@_.-]+$/;
        if (!nameRegex.test(name)) {
            alert('Ошибка: Логин должен содержать только латинские буквы, цифры и символы @ _ . -');
            return false;
        }
        if (name.length < CONFIG.loginMin || name.length > CONFIG.loginMax) {
            alert(`Ошибка: Длина логина должна быть от ${CONFIG.loginMin} до ${CONFIG.loginMax} символов.`);
            return false;
        }

        // === ПРОВЕРКА ПАРОЛЯ ===
        // 1. Пароль не пустой
        if (password.length === 0) {
            alert('Ошибка: Введите пароль.');
            return false;
        }

        // 2. Проверка длины (в символах UTF-8)
        const passwordLength = [...password].length;
        if (passwordLength < CONFIG.passwordMin || passwordLength > CONFIG.passwordMax) {
            alert(`Ошибка: Длина пароля должна быть от ${CONFIG.passwordMin} до ${CONFIG.passwordMax} символов.`);
            return false;
        }

        // 3. Проверка на русские клавиатурные сочетания
        const lowerPassword = password.toLowerCase();
        const foundPattern = KEYBOARD_PATTERNS.find(pattern =>
            lowerPassword.includes(pattern)
        );

        if (foundPattern) {
            alert(`Ошибка: Пароль содержит клавиатурное сочетание: "${foundPattern}".\nПожалуйста, используйте более сложный пароль.`);
            return false;
        }

        // 4. Проверка сложности через zxcvbn
        const result = zxcvbn(password);
        console.log('[zxcvbn] score:', result.score, '| feedback:', result.feedback);

        if (result.score < 2) {
            let msg = 'Ошибка: Пароль слишком простой.';
            if (result.feedback.warning) {
                msg += '\n' + result.feedback.warning;
            }
            if (result.feedback.suggestions && result.feedback.suggestions.length > 0) {
                msg += '\n' + result.feedback.suggestions.join('\n');
            }
            alert(msg);
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
    // Принимает endpoint и объект data (например, { login, hash, salt })
            function sendRequest(endpoint, data) {
        data.timestamp = Date.now();
        console.log('Отправка на сервер:', endpoint, data);

        return fetch(`http://localhost:8080${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        })
        .then(response => {
            if (response.status === 401) {
                console.warn('[session] Сессия истекла (401)');
                localStorage.removeItem('session_id');
                localStorage.removeItem('session_login');
                alert('Сессия истекла. Пожалуйста, войдите заново.');
                return null;
            }
            if (response.status === 403) {
                console.warn('[session] Доступ запрещён (403)');
                alert('Доступ запрещён.');
                return null;
            }
            if (response.status >= 500) {
                console.error('[server] Ошибка сервера:', response.status);
                alert('Ошибка на стороне сервера. Попробуйте позже.');
                return null;
            }
            return response.text();
        })
        .then(result => {
            if (result === null) return null;

            if (result.includes('|')) {
                const parts = result.split('|');
                const message = parts[0];
                const sessionId = parts[1];

                localStorage.setItem('session_id', sessionId);
                localStorage.setItem('session_login', data.login);
                console.log('[session] Сохранён session_id:', sessionId);

                alert('Ответ сервера: ' + message);
                return { success: true, message: message };
            } else {
                alert('Ответ сервера: ' + result);
                return { success: false, message: result };
            }
        })
        .catch(error => {
            alert('Ошибка соединения с сервером! Убедитесь, что сервер запущен на порту 8080.');
            console.error('Ошибка:', error);
            return null;
        });
    }

    // === ЗАПРОС ПРОФИЛЯ (требует сессию) ===
    async function fetchProfile() {
        const sessionId = localStorage.getItem('session_id');
        if (!sessionId) {
            alert('Вы не авторизованы. Войдите.');
            return null;
        }

        try {
            const response = await fetch('http://localhost:8080/profile', {
                method: 'GET',
                headers: {
                    'Authorization': 'Bearer ' + sessionId
                }
            });

            // Обработка 401
            if (response.status === 401) {
                console.warn('[profile] Сессия истекла (401)');
                localStorage.removeItem('session_id');
                localStorage.removeItem('session_login');
                alert('Сессия истекла. Войдите заново.');
                return null;
            }

            const result = await response.text();
            console.log('[profile] Ответ:', result);
            return result;
        } catch (error) {
            console.error('[profile] Ошибка:', error);
            alert('Ошибка соединения с сервером.');
            return null;
        }
    }

    // === ЗАПРОС СОЛИ У СЕРВЕРА ===
    // Возвращает соль пользователя или null, если пользователь не найден
    async function fetchSalt(login) {
        try {
            const response = await fetch(`http://localhost:8080/salt?login=${encodeURIComponent(login)}`);
            if (!response.ok) {
                console.error('[fetchSalt] Сервер вернул ошибку:', response.status);
                return null;
            }
            const salt = await response.text();
            console.log('[fetchSalt] Соль получена:', salt);
            return salt.trim();
        } catch (error) {
            console.error('[fetchSalt] Ошибка запроса:', error);
            return null;
        }
    }

    // ОБРАБОТЧИК КНОПКИ "ВОЙТИ" (валидация + хеширование)
        form.addEventListener('submit', async function(e) {
        e.preventDefault();

        if (!validateLogin()) {
            return;
        }

        const name = nameInput.value.trim();
        const password = passInput.value;

        try {
            const salt = await fetchSalt(name);
            if (!salt) {
                alert('Неверный логин или пароль');
                return;
            }

            const hash = await hashPassword(password, salt);
            console.log('[login] Соль:', salt);
            console.log('[login] Хеш:', hash);

            alert('Данные корректны! (отправка на /login)');
            const result = await sendRequest('/login', { login: name, hash: hash });

            // Если вход успешен — очищаем форму
            if (result && result.success) {
                nameInput.value = '';
                passInput.value = '';
                console.log('[login] Форма очищена');
            }
        } catch (error) {
            console.error('Ошибка хеширования:', error);
            alert('Ошибка при хешировании пароля. Попробуйте ещё раз.');
        }
    });

    // ОБРАБОТЧИК КНОПКИ "ЗАРЕГИСТРИРОВАТЬСЯ" (полная проверка + хеширование)
        document.getElementById('registerBtn').addEventListener('click', async function() {
        if (!validateRegistration()) {
            return;
        }

        const name = nameInput.value.trim();
        const password = passInput.value;

        try {
            const salt = generateSalt();
            console.log('[register] Соль:', salt);

            const hash = await hashPassword(password, salt);
            console.log('[register] Хеш:', hash);

            alert('Данные корректны! (отправка на /register)');
            const result = await sendRequest('/register', { login: name, hash: hash, salt: salt });

            // Очищаем ТОЛЬКО пароль после успешной регистрации
            if (result && result.message && result.message.includes('успешна')) {
                passInput.value = '';
                console.log('[register] Пароль очищен, логин оставлен');
            }
        } catch (error) {
            console.error('Ошибка хеширования:', error);
            alert('Ошибка при хешировании пароля. Попробуйте ещё раз.');
        }
    });

    // ВРЕМЕННО: для отладки
    window.generateSalt = generateSalt;
    window.hashPassword = hashPassword;
    window.fetchProfile = fetchProfile;
    window.fetchSalt = fetchSalt;
})();