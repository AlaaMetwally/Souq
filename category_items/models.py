from datetime import datetime
from category_items import db, login_manager
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# class to create the table user and serialize for json endpoint
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    items = db.relationship('Item', backref='user_item_id', lazy=True)
    categories = db.relationship(
                                'Category',
                                backref='user_category_id', lazy=True)

    def __repr__(self):
        return 'User(username=%s, email=%s)' % (
                                            self.username, self.email)

    @property
    def serialize(self):
        return {
                'id': self.id,
                'username': self.username,
                'email': self.email,
                'items': [i.serialize for i in self.items],
                'categories': [i.serialize for i in self.categories]
        }


# class to create the table category and serialize for json endpoint
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    items = db.relationship('Item', backref='category_id', lazy=True)
    date_category = db.Column(
                            db.DateTime,
                            nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_count = db.Column(db.Integer)
    have_model = db.Column(db.Integer)
    file_name = db.Column(db.String(300))
    data = db.Column(db.LargeBinary)
    faved_user = db.Column(db.Integer, default=0)

    def __repr__(self):
        return
        'Category(id=%d, name=%s, date_category=%s, \
            product_count=%d, have_model=%d)' % (
            self.id, self.name,
            self.date_category, self.product_count, self.have_model)

    @property
    def serialize(self):
        return {
                'id': self.id,
                'name': self.name,
                'items': [i.serialize for i in self.items],
                'date_category': self.date_category,
                'user_id': self.user_id,
                'product_count': self.product_count,
                'have_model': self.have_model,
                'data': self.data,
                'file_name': self.filename,
                'faved_user': self.faved_user
        }


# class to create the table item and serialize for json endpoint
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    cat_id = db.Column(
                    db.Integer, db.ForeignKey('category.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    date_item = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_name = db.Column(db.String(300))
    data = db.Column(db.LargeBinary)
    product_count = db.Column(db.Integer)
    have_model = db.Column(db.Integer)

    def __repr__(self):
        return 'Item(title=%s, date_item=%s)' % (self.title, self.date_item)

    @property
    def serialize(self):
        return {
                'id': self.id,
                'title': self.title,
                'cat_id': self.cat_id,
                'description': self.description,
                'date_item': self.date_item,
                'file_name': self.filename,
                'data': self.data,
                'user_id': self.user_id,
                'product_count': self.product_count,
                'have_model': self.have_model
        }
