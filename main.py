import hashlib
import uuid


class User:
    """
    Базовый класс, представляющий пользователя.
    """
    users = []  # Список для хранения всех пользователей

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = self.hash_password(password)
        # self.users.append([self.username, self.email, self.password])

    @staticmethod
    def hash_password(password):
        salt = uuid.uuid4().hex
#        return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        hash_pass = hashlib.sha256(password.encode('utf-8')).hexdigest()
        #print(hash_pass)
        return hash_pass

    @staticmethod
    def check_password(stored_password, provided_password):
        """
        Проверка пароля.
        """
        hash_pass = User.hash_password(provided_password)
        #print("Проверка пароля.\nstored_password:{}\nprovided_password:{}\nhash_pass:{}".format(stored_password, provided_password, hash_pass))
        return stored_password == hash_pass

    def get_details(self):
        return [self.username, self.email, self.password]


class Customer(User):
    """
    Класс, представляющий клиента, наследующий класс User.
    """

    def __init__(self, username, email, password, address):
        super().__init__(username, email, password)
        self.address = address
        self.user_type = "Customer"
        self.users.append(self.get_details())

    def get_details(self):
        return [self.username, self.email, self.password, self.user_type, self.address]


class Admin(User):
    """
    Класс, представляющий администратора, наследующий класс User.
    """

    def __init__(self, username, email, password, admin_level):
        super().__init__(username, email, password)
        self.admin_level = admin_level
        self.user_type = "Admin"
        self.users.append(self.get_details())

    def get_details(self):
        return [self.username, self.email, self.password, self.user_type, self.admin_level]

    @staticmethod
    def list_users():
        """
        Выводит список всех пользователей.
        """
        for user in User.users:
            print("Имя пользователя: {}, e-mail: {}, {}".format(user[0], user[1], user[3]))

    @staticmethod
    def delete_user(username):
        """
        Удаляет пользователя по имени пользователя.
        """
        try:
            user_to_del = [user for user in User.users if user[0] == username]
            User.users.remove(user_to_del[0])
            return 1
        except ValueError:
            return -1


class AuthenticationService:
    """
    Сервис для управления регистрацией и аутентификацией пользователей.
    """

    def __init__(self):
        self.username = None
        self.session_token = None

    def register(self, user_class, username, email, password, *args):
        """
        Регистрация нового пользователя.
        """

        usernames = [True for user in User.users if user[0] == username]
        if usernames:
            print(f"Пользователь с именем {username} зарегистрирован ранее")
            return -1
        if user_class == "admin":
            admin = Admin(username, email, password, args[0])
            print(f"Пользователь {username} зарегистрирован")
            return admin
        else:
            customer = Customer(username, email, password, args[0])
            print(f"Пользователь {username} зарегистрирован")
            return customer

    def login(self, username, password):
        """
        Аутентификация пользователя.
        """
        stored_password = [user[2] for user in User.users if user[0] == username]
        if User.check_password(stored_password[0], password):
            session_token = uuid.uuid1().hex
            self.username = username
            self.session_token = session_token
        return self.session_token

    def logout(self):
        """
        Выход пользователя из системы.
        """

        self.username = None
        self.session_token = None

    def get_current_user(self):
        """
        Возвращает текущего вошедшего пользователя.
        """
        return [self.username, self.session_token]


# Пример использования

auth_service = AuthenticationService()
#username, email, password, admin_level
admin1 = auth_service.register('admin', 'Admin name 1',  'email_admin1@mail.ru', 'pass123', 1)

#username, email, password, address
customer1 = auth_service.register('customer', 'Customer1', 'customer1@mail.ru', 'customer1_password_1378', 'Москва')
customer2 = auth_service.register('customer', 'Customer2', 'customer2@mail.ru', 'customer2_password_8439', 'Санкт-Петербург')
customer3 = auth_service.register('customer', 'Customer3', 'customer3@mail.ru', 'customer3_password_6148', 'Новосибирск')
customer4 = auth_service.register('customer', 'Customer3', 'customer3@mail.ru', 'customer3_password_6148', 'Новосибирск')

admin1.list_users()
tokin = auth_service.login('Customer1', 'customer1_password_1378')
print("Токин сессии {}".format(tokin))
session = auth_service.get_current_user()
print("Текущая сессия {}".format(session))
auth_service.logout()
session = auth_service.get_current_user()
print("Текущая сессия {}".format(session))
