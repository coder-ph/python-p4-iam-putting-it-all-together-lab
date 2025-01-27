from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique = True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    # created_at = db.Column(db.DateTime, server_default=db.func.now())
    # updated_at = db.Column(db.DateTime, onupdate= db.func.now())
    
    recipes = db.relationship('Recipe', back_populates='user', cascade='all, delete-orphan')
    
    
    @hybrid_property
    def password_hash(self):
        
        raise AttributeError ("password in not readable")
        
    @password_hash.setter
    def password_hash(self, password):
        
        password_hash = bcrypt.generate_password_hash(password.encode('utf-8'))
        self._password_hash = password_hash.decode('utf-8')
        
    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self._password_hash, password.encode('utf-8')
        )
        
    # @validates('username')
    # def validate_username(self, key, value):
    #     if not value:
    #         raise ValueError ('Missing username field')
    #     username = User.query.filter(User.username== value).first()
    #     if username:
    #         return ValueError('This username exist!')
    #     return value
    
    # @validates('_password_hash')
    # def validate_password(self, key, value):
    #     if not value:
    #         raise ValueError('password cannot be empty')
    #     return value
    
    def __repr__(self):
        return f'<User: {self.username}, {self.bio}>'
        
class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate= db.func.now())
    
    
    @validates('title')
    def validate_title(self, key, value):
        if not value:
            raise ValueError ('Missing title field')
        return value
    
    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value or len(value) < 50:
            raise ValueError('instructions must exist and must be at least 50 characters')
        return value
    
    user = db.relationship(User, back_populates='recipes')
    
    def __repr__(self):
        return f'<Recipe: {self.title}, {self.instructions}, {self.minutes_to_complete}>'