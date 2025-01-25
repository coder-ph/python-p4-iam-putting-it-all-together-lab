#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {'message': 'Invalid payload'}, 400
        
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')
        
        if not username or not password:
            return {'message': 'username and password required'}, 422
        
        if User.query.filter(User.username == username).first():
            return {'message': 'username already exist'}, 400
        
        new_user = User(username=username, image_url=image_url, bio=bio)
        new_user.password_hash = password
        
        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return new_user.to_dict(), 201
        except Exception as e:
            db.session.rollback()
            return {'message': f'Error{str(e)}'}, 500

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'message':"401: Not authorized"}, 401
        
        user = User.query.get(user_id)
        if not user:
            return {'message': 'user not found'}, 404
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {'message': 'Invalid payload'}, 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'message': 'password and username required'}, 400
        
        user = User.query.filter(User.username == username).first()
        
        if not user or not user.authenticate(password):
            return {'message': "Invalid username or password"}, 401
        
        session['user_id']= user.id
        return user.to_dict(), 200
            
class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.clear()
            return {'message': 'logged out successfully'}, 204
        else:
            return {'message': 'Unauthorized action'}, 401

class RecipeIndex(Resource):
    def get(self):
        # Check if the user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return {'message': "401: Not authorized"}, 401
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        if not recipes:
            return {'message': 'No recipes found'}, 404
        recipe_list = [recipe.to_dict() for recipe in recipes]
        return recipe_list, 200  
        
    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'message': '401:not authorized'}, 401
        
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')
        
        errors = {}
        if not title:
            errors['title'] = 'Title is required'
        if not instructions or len(instructions) < 50:
            errors['instructions'] = 'instructions must be at least 50 characters'
        if not minutes_to_complete or not isinstance(minutes_to_complete, int) or minutes_to_complete <=0:
            errors['minutes_to_complete'] = 'minutes to complete must be a positive number'
            
        if errors:
            return {'errors': errors}, 422
        
        new_recipe = Recipe(
            title = title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user=user
        )
        
        try:
            db.session.add(new_recipe)
            db.session.commit()
            return {
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
            }, 201
        except Exception as e:
            db.session.rollback()
            return {'message': f'Error: {str(e)}'}, 500
            

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)