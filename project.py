# Імпортуємо модуль sqlite3 для роботи з базою даних SQLite
import sqlite3  
# Імпортуємо модуль QtWidgets з бібліотеки PyQt5 для створення графічного інтерфейсу користувача
from PyQt5 import QtWidgets, QtCore
# Імпортуємо файл project_1_ui, який містить клас Ui_MainWindow з описом інтерфейсу
import project_1_ui  
#Цей код імпортує клас QWebEngineView з модуля PyQt5.QtWebEngineWidgets який надає зручний інтерфейс для роботи з веб-контентом в програмах PyQt5.
from PyQt5.QtWebEngineWidgets import QWebEngineView
#Імпортуємо бібліотеку для роботи з регулярними виразами
import re
#Імпортуємо бібліотеку для хешування даних
import hashlib
#Імпортуємо бібліотеку для хешування паролів з використанням алгоритму bcrypt
import bcrypt

from PyQt5.QtWidgets import QMessageBox, QLineEdit


# З'єднуємося з базою даних SQLite
db = sqlite3.connect('database.db')
cursor = db.cursor()

# Створюємо таблицю користувачів у базі даних, якщо вона ще не існує
cursor.execute('''CREATE TABLE IF NOT EXISTS users(
    login TEXT,
    password TEXT
)''')
db.commit()




class PasswordValidator:
    def is_valid(password):
        # Перевірка довжини пароля (принаймні 8 символів)
        if len(password) < 8:
            return False
        
        # Перевірка наявності принаймні однієї цифри
        if not re.search(r'\d', password):
            return False
        
        # Перевірка наявності принаймні однієї великої літери
        if not re.search(r'[A-Z]', password):
            return False
        
        # Перевірка наявності принаймні одного спецсимволу
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        
        if not re.search(r'1234567890', password):
            return False
        
        return True

# Виводимо на екран усі записи у таблиці користувачів (це тимчасова частина для дебагу)
for i in cursor.execute('SELECT * FROM users'):
    print(i)
class AccountsWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Список акаунтів')
        self.resize(300, 200)

        self.layout = QtWidgets.QVBoxLayout()
        self.setLayout(self.layout)

        self.accounts_list = QtWidgets.QListWidget()
        self.layout.addWidget(self.accounts_list)

        self.load_accounts()

    def load_accounts(self):
        cursor.execute('SELECT login FROM users')
        accounts = cursor.fetchall()
        for account in accounts:
            self.accounts_list.addItem(account[0])

class delakaunt(QtWidgets.QMainWindow, project_1_ui.Ui_MainWindow):
    def __init__(self):
        super(delakaunt, self).__init__()
        # Ініціалізуємо інтерфейс
        self.setupUi(self)
        # Встановлюємо текст та параметри елементів інтерфейсу
        self.label.setText('')
        self.label_2.setText('Видалення акаунту')
        self.lineEdit.setPlaceholderText('Введіть логін')
        self.lineEdit_2.setPlaceholderText('Введіть пароль')
        self.pushButton.setText('Видалити акаунт')
        self.pushButton_2.setText('Відміна')
        self.pushButton_3.setText('Вхід')
        self.pushButton_4.setText('Показати акаунти')
        self.pushButton_5.setText('Змінити пароль')
        self.setWindowTitle('Видалення акаунту')

        # Під'єднуємо кнопки до відповідних методів
        self.pushButton.clicked.connect(self.delete_account)
        self.pushButton_2.clicked.connect(self.cancel)
        self.pushButton_3.clicked.connect(self.login)  
        self.pushButton_4.clicked.connect(self.show_accounts)
        self.pushButton_5.clicked.connect(self.change_password)
       
      
        
    def show_accounts(self):
        self.accounts_window = AccountsWindow()
        self.accounts_window.show()
    def login(self):
        self.login = Login()
        self.login.show()
        self.hide()
    
    def delete_account(self):
    # Отримуємо логін користувача з поля введення
        user_login = self.lineEdit.text()

        # Видаляємо всі записи з бази даних, де логін відповідає введеному користувачем
        cursor.execute(f'DELETE FROM users WHERE login="{user_login}"')
        db.commit()

        # Перевіряємо, чи видалення було успішним
        if cursor.rowcount > 0:
            self.label.setText(f'Акаунт {user_login} успішно видалено!')
        else:
            self.label.setText('Користувача з таким логіном не знайдено!')
    def reg(self):
    # Перевіряємо, чи користувач увійшов у систему
        if self.logged_in:
            self.reg = register()
            self.reg.show()
            self.hide()
        else:
            # Якщо користувач не увійшов, показуємо повідомлення про помилку
            self.label.setText('Спочатку увійдіть в систему!')
    def cancel(self):
        # Закриваємо вікно видалення акаунту
        self.login = Login()
        self.login.show()
        self.hide()
    def change_password(self):
        # Отримуємо логін та старий пароль користувача
        user_login = self.lineEdit.text()
        old_password = self.lineEdit_2.text()

        # Перевіряємо, чи логін та старий пароль не порожні
        if not user_login or not old_password:
            self.label.setText('Будь ласка, введіть логін та старий пароль')
            return

        # Перевіряємо, чи існує користувач з таким логіном і паролем
        cursor.execute(f'SELECT * FROM users WHERE login="{user_login}" AND password="{old_password}"')
        existing_user = cursor.fetchone()

        # Перевіряємо, чи користувач існує і чи введений старий пароль правильний
        if existing_user:
            # Показуємо діалогове вікно для введення нового пароля
            new_password, ok = QtWidgets.QInputDialog.getText(self, 'Зміна паролю', 'Введіть новий пароль:', QLineEdit.Password)

            # Перевіряємо, чи був натиснутий OK і чи новий пароль не порожній
            if ok and new_password:
                # Перевіряємо, чи новий пароль відрізняється від старого
                if new_password != old_password:
                    # Оновлюємо пароль користувача
                    cursor.execute(f'UPDATE users SET password="{new_password}" WHERE login="{user_login}"')
                    db.commit()
                    self.label.setText(f'Пароль для акаунту {user_login} успішно змінено!')
                    # Висвітлюємо повідомлення про зміну паролю
                    QMessageBox.information(self, 'Зміна паролю', f'Пароль для акаунту {user_login} успішно змінено!')
                else:
                    QMessageBox.warning(self, 'Помилка', 'Новий пароль повинен відрізнятися від старого!')
            else:
                QMessageBox.warning(self, 'Помилка', 'Введено некоректний пароль!')
        else:
            self.label.setText('Користувача з таким логіном та паролем не знайдено!')
# Клас для реєстрації нових користувачів
class register(QtWidgets.QMainWindow, project_1_ui.Ui_MainWindow):
    def __init__(self):
        super(register, self).__init__()
        # Ініціалізуємо інтерфейс.
        self.setupUi(self)
        # Встановлюємо текст та параметри елементів інтерфейсу
        self.label.setText('')
        self.label_2.setText('Реєстрація')
        self.lineEdit.setPlaceholderText('Введіть Логін')
        self.lineEdit_2.setPlaceholderText('Введіть Пароль')
        self.pushButton.setText('Реєстрація')
        self.pushButton_2.setText('Вхід')
        self.pushButton_3.setText('Видалити акаунт') 
        self.pushButton_4.setText('Показати акаунти')
        self.pushButton_5.setText('Змінити пароль')
        self.setWindowTitle('Реєстрація')
        

        # Під'єднуємо кнопки до відповідних методів
        self.pushButton.pressed.connect(self.reg)
        self.pushButton_2.pressed.connect(self.login)
        self.pushButton_3.clicked.connect(self.open_delete_account)
        self.pushButton_4.clicked.connect(self.show_accounts)
        self.pushButton_5.clicked.connect(self.change_password)
        

    def show_accounts(self):
        self.accounts_window = AccountsWindow()
        self.accounts_window.show()
    # Додайє метод для відкриття вікна видалення акаунту:
    def open_delete_account(self):
        self.delete_account_window = delakaunt()
        self.delete_account_window.show()
        self.hide()
    
    # Метод переходу до вікна входу
    def login(self):
        self.login = Login()
        self.login.show()
        self.hide()

    # Метод реєстрації нового користувача
    def reg(self):
        # Отримуємо дані з полів введення
        user_login = self.lineEdit.text()
        user_password = self.lineEdit_2.text()

        # Перевіряємо, чи поля не порожні
        if not user_login or not user_password:
            self.label.setText('Будь ласка, введіть логін та пароль')
            return

        # Перевіряємо, чи користувач з таким логіном вже існує в базі даних
        cursor.execute(f'SELECT login FROM users WHERE login="{user_login}"')
        existing_user = cursor.fetchone()

        if existing_user:
            self.label.setText('Такий акаунт вже існує!')
            return

        # Перевіряємо надійність паролю
        if not PasswordValidator.is_valid(user_password):
            reply = QMessageBox.question(self, 'Пароль ненадійний', 'Ви впевнені, що хочете використовувати такий ненадійний пароль?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return

        # Додаємо користувача до бази даних
        cursor.execute(f'INSERT INTO users VALUES ("{user_login}", "{user_password}")')
        db.commit()
        self.label.setText(f'Акаунт {user_login} успішно зареєстровано!')
    def change_password(self):
        # Отримуємо логін та старий пароль користувача
        user_login = self.lineEdit.text()
        old_password = self.lineEdit_2.text()

        # Перевіряємо, чи логін та старий пароль не порожні
        if not user_login or not old_password:
            self.label.setText('Будь ласка, введіть логін та старий пароль')
            return

        # Перевіряємо, чи існує користувач з таким логіном і паролем
        cursor.execute(f'SELECT * FROM users WHERE login="{user_login}" AND password="{old_password}"')
        existing_user = cursor.fetchone()

        # Перевіряємо, чи користувач існує і чи введений старий пароль правильний
        if existing_user:
            # Показуємо діалогове вікно для введення нового пароля
            new_password, ok = QtWidgets.QInputDialog.getText(self, 'Зміна паролю', 'Введіть новий пароль:', QLineEdit.Password)

            # Перевіряємо, чи був натиснутий OK і чи новий пароль не порожній
            if ok and new_password:
                # Перевіряємо, чи новий пароль відрізняється від старого
                if new_password != old_password:
                    # Оновлюємо пароль користувача
                    cursor.execute(f'UPDATE users SET password="{new_password}" WHERE login="{user_login}"')
                    db.commit()
                    self.label.setText(f'Пароль для акаунту {user_login} успішно змінено!')
                    # Висвітлюємо повідомлення про зміну паролю
                    QMessageBox.information(self, 'Зміна паролю', f'Пароль для акаунту {user_login} успішно змінено!')
                else:
                    QMessageBox.warning(self, 'Помилка', 'Новий пароль повинен відрізнятися від старого!')
            else:
                QMessageBox.warning(self, 'Помилка', 'Введено некоректний пароль!')
        else:
            self.label.setText('Користувача з таким логіном та паролем не знайдено!')


# Клас для авторизації користувачів.
class Login(QtWidgets.QMainWindow, project_1_ui.Ui_MainWindow):
    def __init__(self):
        super(Login, self).__init__()
        # Ініціалізуємо інтерфейс
        self.setupUi(self)
        # Встановлюємо текст та параметри елементів інтерфейсу
        self.label.setText('')
        self.label_2.setText('Логін')
        self.lineEdit.setPlaceholderText('Введіть логін')
        self.lineEdit_2.setPlaceholderText('Введіть пароль')
        self.pushButton.setText('Вхід')
        self.pushButton_2.setText('Реєстрація')
        self.pushButton_3.setText('Видалити акаунт')
        self.pushButton_4.setText('Показати акаунти')
        self.pushButton_5.setText('Змінити пароль')
        self.setWindowTitle('Вхід')
        
        # Під'єднуємо кнопки до відповідних методів
        self.pushButton_4.clicked.connect(self.show_accounts)
        self.pushButton.pressed.connect(self.login_attempt)
        self.pushButton_2.pressed.connect(self.reg)
        self.pushButton_3.clicked.connect(self.open_delete_account)
        self.pushButton_5.clicked.connect(self.change_password)
       
    # Створюємо змінну, щоб зберігати стан входу користувача
        self.logged_in = False

    def show_accounts(self):
        self.accounts_window = AccountsWindow()
        self.accounts_window.show()

    # Метод переходу до вікна реєстрації.
    def reg(self):
    # Перевіряємо, чи користувач увійшов у систему
        if self.logged_in:
            self.reg = register()
            self.reg.show()
            self.hide()
        else:
            # Якщо користувач не увійшов, показуємо повідомлення про помилку
            self.label.setText('Спочатку увійдіть в систему!')

    def open_delete_account(self):
        self.delete_account_window = delakaunt()
        self.delete_account_window.show()
        self.hide()

    # Метод авторизації користувача
    def login_attempt(self):
        # Отримуємо дані з полів введення.
        user_login = self.lineEdit.text()
        user_password = self.lineEdit_2.text()

        # Перевіряємо, чи введені дані не порожні
        if len(user_login) == 0 or len(user_password) == 0:
            return

        # Перевіряємо, чи існує користувач з таким логіном у базі даних
        cursor.execute(f'SELECT * FROM users WHERE login="{user_login}" AND password="{user_password}"')
        existing_user = cursor.fetchone()

        # Перевіряємо правильність введеного пароля та логіна.
        if existing_user:
            # Якщо користувач існує, встановлюємо флаг logged_in в True
            self.logged_in = True
            # Відкриття файлу project_.py
            import subprocess
            subprocess.Popen(["python", "project_.py"])
            # Ваша логіка для переходу до головного вікна програми
        else:
            # Якщо користувача не знайдено, виводимо повідомлення з запитом на реєстрацію нового акаунту
            reply = QtWidgets.QMessageBox.question(self, 'Реєстрація нового акаунту', 'Користувача з таким логіном і паролем не знайдено. Бажаєте зареєструвати новий акаунт?',
                                                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
            if reply == QtWidgets.QMessageBox.Yes:
                self.reg = register()
                self.reg.show()
                self.hide()

    def change_password(self):
        # Отримуємо логін та старий пароль користувача
        user_login = self.lineEdit.text()
        old_password = self.lineEdit_2.text()

        # Перевіряємо, чи логін та старий пароль не порожні
        if not user_login or not old_password:
            self.label.setText('Будь ласка, введіть логін та старий пароль')
            return

        # Перевіряємо, чи існує користувач з таким логіном і паролем
        cursor.execute(f'SELECT * FROM users WHERE login="{user_login}" AND password="{old_password}"')
        existing_user = cursor.fetchone()

        # Перевіряємо, чи користувач існує і чи введений старий пароль правильний
        if existing_user:
            # Показуємо діалогове вікно для введення нового пароля
            new_password, ok = QtWidgets.QInputDialog.getText(self, 'Зміна паролю', 'Введіть новий пароль:', QLineEdit.Password)

            # Перевіряємо, чи був натиснутий OK і чи новий пароль не порожній
            if ok and new_password:
                # Перевіряємо, чи новий пароль відрізняється від старого
                if new_password != old_password:
                    # Оновлюємо пароль користувача
                    cursor.execute(f'UPDATE users SET password="{new_password}" WHERE login="{user_login}"')
                    db.commit()
                    self.label.setText(f'Пароль для акаунту {user_login} успішно змінено!')
                    # Висвітлюємо повідомлення про зміну паролю
                    QMessageBox.information(self, 'Зміна паролю', f'Пароль для акаунту {user_login} успішно змінено!')
                else:
                    QMessageBox.warning(self, 'Помилка', 'Новий пароль повинен відрізнятися від старого!')
            else:
                QMessageBox.warning(self, 'Помилка', 'Введено некоректний пароль!')
        else:
            self.label.setText('Користувача з таким логіном та паролем не знайдено!')
    
    


App = QtWidgets.QApplication([])
window = Login()
window.show()
App.exec()

