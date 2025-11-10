from flask import Flask, flash, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from passlib.hash import pbkdf2_sha256
from functools import wraps

app = Flask(__name__)
app.secret_key = 'CambiamePorUnaClaveSuperSegura123!'  # Clave secreta segura

# Configuración de la base de datos
app.config['MYSQL_HOST'] = 'bk04shedziewaurflocq-mysql.services.clever-cloud.com'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'ukrbsge1qc5hzucq'
app.config['MYSQL_PASSWORD'] = 'iCVyHgfRRLOkPiyl034w'
app.config['MYSQL_DB'] = 'bk04shedziewaurflocq'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

# -------------------------------
# DECORADORES
# -------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logueado' not in session:
            flash("Debes iniciar sesión", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logueado' not in session or session.get('id_rol') != 1:
            flash("Acceso denegado: solo administradores", "danger")
            return redirect(url_for('inicio'))
        return f(*args, **kwargs)
    return decorated

# -------------------------------
# LOGIN
# -------------------------------
@app.route('/accesologin', methods=['POST'])
def accesologin():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not email or not password:
        flash("Completa todos los campos", "warning")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        try:
            # Intentamos verificar como hash
            password_correcta = pbkdf2_sha256.verify(password, user['password'])
        except ValueError:
            # Si falla, es porque estaba en texto plano
            if password == user['password']:
                # Convertimos la contraseña a hash automáticamente
                hashed = pbkdf2_sha256.hash(password)
                cursor.execute("UPDATE usuario SET password=%s WHERE id=%s", (hashed, user['id']))
                mysql.connection.commit()
                password_correcta = True
            else:
                password_correcta = False

        if password_correcta:
            # Login exitoso
            session['logueado'] = True
            session['id'] = user['id']
            session['nombre'] = user['nombre']
            session['id_rol'] = user['id_rol']
            flash(f"Bienvenido {user['nombre']}", "success")
            return redirect(url_for('admin') if user['id_rol'] == 1 else url_for('inicio'))
    
    flash("Usuario o contraseña incorrectos", "danger")
    return redirect(url_for('login'))
# -------------------------------
# REGISTRO DE USUARIOS
# -------------------------------
@app.route('/crearusuario', methods=['GET', 'POST'])
def crearusuario():
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        email = request.form.get('email')
        password = request.form.get('password')

        if not nombre or not email or not password:
            flash("Todos los campos son obligatorios", "warning")
            return redirect(url_for('registro'))

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            flash("Este correo ya está registrado", "warning")
            return redirect(url_for('registro'))

        hashed_password = pbkdf2_sha256.hash(password)
        cursor.execute(
            "INSERT INTO usuario (nombre,email,password,id_rol) VALUES (%s,%s,%s,2)",
            (nombre,email,hashed_password)
        )
        mysql.connection.commit()
        cursor.close()
        flash("Usuario registrado exitosamente", "success")
        return redirect(url_for('usuario'))

    return render_template('registro.html')

# -------------------------------
# RUTAS DE USUARIOS
# -------------------------------
@app.route('/usuario')
@admin_required
def usuario():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, nombre, email, password FROM usuario")
    usuarios = cursor.fetchall()
    cursor.close()
    return render_template('usuario.html', usuarios=usuarios)

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    cursor = mysql.connection.cursor()
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        id_rol = int(request.form['id_rol'])  # nuevo rol
        cursor.execute("""
            UPDATE usuario SET nombre=%s, email=%s, password=%s, id_rol=%s WHERE id=%s
        """, (nombre, email, password, id_rol, id))
        mysql.connection.commit()
        cursor.close()
        
        # ⚡ Actualizar sesión si el usuario está editando su propio rol
        if session.get('id') == id:
            session['id_rol'] = id_rol
            session['nombre'] = nombre  # opcional si también cambió
        
        flash('Usuario actualizado correctamente', 'success')
        return redirect(url_for('usuario'))
    else:
        cursor.execute("SELECT * FROM usuario WHERE id=%s", (id,))
        usuario = cursor.fetchone()
        cursor.close()
        return render_template('editar_usuario.html', usuario=usuario)


@app.route('/eliminar_usuario/<int:id>')
@admin_required
def eliminar_usuario(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM usuario WHERE id=%s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash("Usuario eliminado correctamente", "info")
    return redirect(url_for('usuario'))

# -------------------------------
# RUTAS PRINCIPALES
# -------------------------------
@app.route('/')
def inicio():
    if 'logueado' in session:
        if session.get('id_rol') == 1:
            return redirect(url_for('admin'))
        else:
            return render_template('inicio_usuario.html')
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/registro')
def registro():
    return render_template('registro.html')

@app.route('/admin')
@admin_required
def admin():
    cursor = mysql.connection.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM producto")
    resultado = cursor.fetchone()
    total_productos = resultado['total']

    cursor.execute("SELECT COUNT(*) AS total FROM usuario")
    resultado = cursor.fetchone()
    total_usuarios = resultado['total']

    cursor.execute("SELECT COUNT(*) AS total FROM producto")
    resultado = cursor.fetchone()
    total_ventas = resultado['total']

    cursor.close()

    return render_template(
        'admin.html',
        total_productos=total_productos,
        total_usuarios=total_usuarios,
    )

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("Sesión cerrada correctamente", "info")
    return redirect(url_for('login'))

# -------------------------------
# PRODUCTOS
# -------------------------------
@app.route('/gestionproducto')
@admin_required
def gestionproducto():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM producto")
    productos = cursor.fetchall()
    cursor.close()
    return render_template('gestionproducto.html', productos=productos)

@app.route('/agregar', methods=['POST'])
@admin_required
def agregar():
    try:
        datos = (
            request.form['codigo'],
            request.form['nombre'],
            request.form['categoria'],
            int(request.form['cantidad']),
            float(request.form['precio_compra']),
            float(request.form['precio_venta']),
            request.form.get('proveedor'),
            request.form.get('fecha_compra'),
            request.form.get('fecha_vencimiento')
        )
        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO producto (codigo,nombre,categoria,cantidad,precio_compra,precio_venta,proveedor,fecha_compra,fecha_vencimiento) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", datos
        )
        mysql.connection.commit()
        cursor.close()
        flash("Producto agregado correctamente", "success")
    except Exception as e:
        flash("Error al agregar producto: " + str(e), "danger")
    return redirect(url_for('gestionproducto'))

@app.route('/editar/<int:id>', methods=['POST'])
@admin_required
def editar_producto(id):
    try:
        # Obtener datos del formulario
        codigo = request.form['codigo']
        nombre = request.form['nombre']
        categoria = request.form['categoria']
        cantidad = int(request.form['cantidad'])
        precio_compra = float(request.form['precio_compra'])
        precio_venta = float(request.form['precio_venta'])
        proveedor = request.form.get('proveedor') or ''
        fecha_compra = request.form.get('fecha_compra') or None
        fecha_vencimiento = request.form.get('fecha_vencimiento') or None

        print("ID recibido:", id)
        print("Datos recibidos:")
        print(codigo, nombre, categoria, cantidad, precio_compra, precio_venta, proveedor, fecha_compra, fecha_vencimiento)

        cursor = mysql.connection.cursor()

        # Verificar si el código ya existe en otro producto
        cursor.execute("SELECT id FROM producto WHERE codigo = %s AND id != %s", (codigo, id))
        duplicado = cursor.fetchone()
        print("¿Código duplicado?:", duplicado)

        if duplicado:
            flash("Ya existe otro producto con el mismo código.", "warning")
            return redirect(url_for('gestionproducto'))

        # Ejecutar actualización
        cursor.execute("""
            UPDATE producto
            SET codigo=%s,
                nombre=%s,
                categoria=%s,
                cantidad=%s,
                precio_compra=%s,
                precio_venta=%s,
                proveedor=%s,
                fecha_compra=%s,
                fecha_vencimiento=%s
            WHERE id=%s
        """, (
            codigo, nombre, categoria, cantidad,
            precio_compra, precio_venta, proveedor,
            fecha_compra, fecha_vencimiento, id
        ))

        print("Filas modificadas:", cursor.rowcount)

        mysql.connection.commit()

        if cursor.rowcount == 0:
            flash("No se realizaron cambios en el producto.", "info")
        else:
            flash("Producto actualizado correctamente.", "success")

    except Exception as e:
        flash("Error al actualizar producto: " + str(e), "danger")

    finally:
        cursor.close()

    return redirect(url_for('listaproducto'))

@app.route('/eliminar/<int:id>')
@admin_required
def eliminar_producto(id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM producto WHERE id=%s", (id,))
    mysql.connection.commit()
    cursor.close()
    flash("Producto eliminado", "info")
    return redirect(url_for('gestionproducto'))

@app.route('/listaproducto', methods=['GET', 'POST'])
@admin_required
def listaproducto():
    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        try:
            codigo = request.form['codigo']

            # Verificar si el código ya existe
            cursor.execute("SELECT COUNT(*) FROM producto WHERE codigo = %s", (codigo,))
            resultado = cursor.fetchone()
            existe = resultado[0] if resultado else 0

            if existe:
                flash("Ya existe un producto con ese código.", "warning")
                return redirect(url_for('listaproducto'))

            # Insertar nuevo producto
            datos = (
                codigo,
                request.form['nombre'],
                request.form['categoria'],
                int(request.form['cantidad']),
                float(request.form['precio_compra']),
                float(request.form['precio_venta']),
                request.form.get('proveedor'),
                request.form.get('fecha_compra'),
                request.form.get('fecha_vencimiento')
            )

            cursor.execute("""
                INSERT INTO producto (
                    codigo, nombre, categoria, cantidad,
                    precio_compra, precio_venta, proveedor,
                    fecha_compra, fecha_vencimiento
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, datos)

            mysql.connection.commit()
            flash("Producto registrado correctamente.", "success")

        except Exception as e:
            flash("Error al registrar producto: " + str(e), "danger")
            return redirect(url_for('listaproducto'))

    # Mostrar todos los productos
    cursor.execute("SELECT * FROM producto")
    productos = cursor.fetchall()
    cursor.close()
    return render_template('listaproducto.html', productos=productos)

# -------------------------------
# CONTACTO Y PÁGINAS
# -------------------------------
@app.route('/contacto_post', methods=['GET','POST'])
def contacto_post():
    usuario = {'nombre':'','email':'','mensaje':''}
    if request.method == 'POST':
        usuario['nombre'] = request.form.get('nombre','')
        usuario['email'] = request.form.get('email','')
        usuario['mensaje'] = request.form.get('mensaje','')
    return render_template('contacto_post.html', usuario=usuario)

@app.route('/acercade')
def acercade():
    return render_template('acercade.html')

@app.route('/index')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True, port=8000)
