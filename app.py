import tkinter as tk
from tkinter import ttk, messagebox
import psycopg2
from psycopg2 import Error
from mlkem_modulo import simular_mlkem768_kem, cifrar_password_xor

# ---------------------------------------------------------
# Conexión a PostgreSQL (Base de Datos: sistema_usuarios_mlkem)
# ---------------------------------------------------------
def conectar_db():
    try:
        conexion = psycopg2.connect(
            host="localhost",
            port="5433",  # Cambia a 5433 si tu PostgreSQL usa ese puerto
            user="postgres",
            password="12345678",  # Tu contraseña de PostgreSQL
            database="sistema_usuarios_mlkem",
            client_encoding="utf-8"
        )
        return conexion
    except Error as e:
        messagebox.showerror("Error de Conexión", f"No se pudo conectar a PostgreSQL:\n{e}")
        return None

# ---------------------------------------------------------
# Aplicación Principal Tkinter
# ---------------------------------------------------------
class AppUsuariosMLKEM:
    def __init__(self, root):
        self.root = root
        self.root.title("Gestión de Usuarios - Criptografía Post-Cuántica (ML-KEM)")
        self.root.geometry("480x540")
        self.root.resizable(False, False)

        self.container = tk.Frame(self.root)
        self.container.pack(fill="both", expand=True)

        self.mostrar_pantalla_registro()

    def limpiar_pantalla(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    # ---------------------------------------------------------
    # Pantalla de Registro
    # ---------------------------------------------------------
    def mostrar_pantalla_registro(self):
        self.limpiar_pantalla()

        tk.Label(self.container, text="Registro (Protección ML-KEM)", font=("Arial", 15, "bold")).pack(pady=15)

        form_frame = tk.Frame(self.container)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Nombre completo:", font=("Arial", 10)).grid(row=0, column=0, sticky="w", pady=5)
        self.entry_nombre = tk.Entry(form_frame, width=30)
        self.entry_nombre.grid(row=0, column=1, pady=5)

        tk.Label(form_frame, text="Correo electrónico:", font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=5)
        self.entry_email = tk.Entry(form_frame, width=30)
        self.entry_email.grid(row=1, column=1, pady=5)

        tk.Label(form_frame, text="Nombre de usuario:", font=("Arial", 10)).grid(row=2, column=0, sticky="w", pady=5)
        self.entry_usuario = tk.Entry(form_frame, width=30)
        self.entry_usuario.grid(row=2, column=1, pady=5)

        tk.Label(form_frame, text="Contraseña:", font=("Arial", 10)).grid(row=3, column=0, sticky="w", pady=5)
        self.entry_password = tk.Entry(form_frame, width=30, show="*")
        self.entry_password.grid(row=3, column=1, pady=5)

        tk.Button(
            self.container, 
            text="Registrarse con ML-KEM", 
            bg="#673AB7", 
            fg="white", 
            font=("Arial", 10, "bold"), 
            width=25, 
            command=self.registrar_usuario
        ).pack(pady=15)

        tk.Button(
            self.container, 
            text="¿Ya tienes cuenta? Inicia Sesión", 
            fg="blue", 
            bd=0, 
            cursor="hand2", 
            command=self.mostrar_pantalla_login
        ).pack(pady=5)

    def registrar_usuario(self):
        nombre = self.entry_nombre.get().strip()
        email = self.entry_email.get().strip()
        usuario = self.entry_usuario.get().strip()
        password = self.entry_password.get().strip()
        
        if not (nombre and email and usuario and password):
            messagebox.showwarning("Campos vacíos", "Por favor llena todos los campos.")
            return

        # 1. Generar intercambio ML-KEM y derivar el secreto compartido
        pub_key, ciphertext, shared_secret = simular_mlkem768_kem()
        
        # 2. Cifrar contraseña con el secreto mediante XOR
        password_cifrada = cifrar_password_xor(password, shared_secret)

        db = conectar_db()
        if db:
            try:
                cursor = db.cursor()
                query = """
                    INSERT INTO usuarios (nombre, email, usuario, password, mlkem_public_key, mlkem_ciphertext, secreto_compartido)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(query, (nombre, email, usuario, password_cifrada, pub_key, ciphertext, shared_secret))
                db.commit()
                
                messagebox.showinfo(
                    "Éxito Post-Cuántico", 
                    f"Usuario registrado correctamente con ML-KEM-768.\n\n"
                    f"Secreto Compartido Derivado:\n{shared_secret[:25]}..."
                )
                self.mostrar_pantalla_login()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo registrar:\n{e}")
            finally:
                cursor.close()
                db.close()

    # ---------------------------------------------------------
    # Pantalla de Login
    # ---------------------------------------------------------
    def mostrar_pantalla_login(self):
        self.limpiar_pantalla()

        tk.Label(self.container, text="Iniciar Sesión (ML-KEM)", font=("Arial", 15, "bold")).pack(pady=20)

        form_frame = tk.Frame(self.container)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Usuario:", font=("Arial", 10)).grid(row=0, column=0, sticky="w", pady=5)
        self.entry_login_usuario = tk.Entry(form_frame, width=30)
        self.entry_login_usuario.grid(row=0, column=1, pady=5)

        tk.Label(form_frame, text="Contraseña:", font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=5)
        self.entry_login_password = tk.Entry(form_frame, width=30, show="*")
        self.entry_login_password.grid(row=1, column=1, pady=5)

        tk.Button(
            self.container, 
            text="Ingresar", 
            bg="#2196F3", 
            fg="white", 
            font=("Arial", 10, "bold"), 
            width=20, 
            command=self.validar_login
        ).pack(pady=15)

        tk.Button(
            self.container, 
            text="¿No tienes cuenta? Regístrate aquí", 
            fg="blue", 
            bd=0, 
            cursor="hand2", 
            command=self.mostrar_pantalla_registro
        ).pack(pady=5)

    def validar_login(self):
        usuario = self.entry_login_usuario.get().strip()
        password_ingresada = self.entry_login_password.get().strip()

        if not usuario or not password_ingresada:
            messagebox.showwarning("Advertencia", "Ingresa usuario y contraseña.")
            return

        db = conectar_db()
        if db:
            try:
                cursor = db.cursor()
                # Consultamos el secreto_compartido junto con el hash del password
                sql = "SELECT nombre, password, secreto_compartido FROM usuarios WHERE usuario = %s"
                cursor.execute(sql, (usuario,))
                resultado = cursor.fetchone()

                if resultado:
                    nombre, password_bd, shared_secret = resultado
                    
                    # Ciframos la contraseña que ingresa el usuario con el secreto_compartido recuperado
                    password_ingresada_cifrada = cifrar_password_xor(password_ingresada, shared_secret)
                    
                    if password_ingresada_cifrada == password_bd:
                        messagebox.showinfo("Bienvenido", f"¡Bienvenido de nuevo, {nombre}!")
                    else:
                        messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
                else:
                    messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
            except Error as e:
                messagebox.showerror("Error", f"Error de consulta:\n{e}")
            finally:
                cursor.close()
                db.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = AppUsuariosMLKEM(root)
    root.mainloop()