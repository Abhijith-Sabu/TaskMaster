from flask import Flask,render_template,redirect , url_for , request,jsonify

from flask_bootstrap import Bootstrap5
app=Flask(__name__)
app.config['SECRET_KEY'] = 'ftyfguhijijokopkopkpok'
Bootstrap5(app=app)


to_do_list=[]



@app.route('/', methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        text = request.form.get('item')
        if text:
            to_do_list.append({'text': text, 'done': False})
    enumerated_list = list(enumerate(to_do_list, start=1))
    return render_template('home.html', enumerated_list=enumerated_list)


@app.route('/del/<int:index>',methods=['POST','GET'])
def del_to_do(index):
    if 1<=index <=len(to_do_list):
        to_do_list.pop(index-1)
        return redirect(url_for('home'))

@app.route('/toggle_done/<int:index>', methods=['POST'])
def toggle_done(index):
    if 1 <= index <= len(to_do_list):
        if 'done' not in to_do_list[index-1]:
            to_do_list[index-1] = {'text': to_do_list[index-1], 'done': True}
        else:
            to_do_list[index-1]['done'] = not to_do_list[index-1]['done']
    return jsonify({'success': True})
if __name__ == '__main__':
    app.run(debug=True)

