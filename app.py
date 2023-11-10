from flask import Flask, render_template, url_for, request, redirect,json
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin,login_user, login_required, logout_user, current_user
from wtforms.validators import ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime


db = SQLAlchemy()
app = Flask(__name__)
bcrypt=Bcrypt(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root@localhost/ticketing"
#app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://admin:Ticket1234@database-1.cazb9kcap4ev.us-east-1.rds.amazonaws.com/ticketing"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.secret_key = "ramdom32k1"
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    mobile = db.Column(db.String(10), nullable=False, unique=True)
    team = db.Column(db.String(30), nullable=False)
    role = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    rfc=db.relationship('Change_Table', backref="RFC")
    

class Change_Table(db.Model):
    cr=db.Column(db.Integer, primary_key=True)
    requester=db.Column(db.String(40), nullable=False)
    requesterid= db.Column(db.Integer,db.ForeignKey('user.id'))
    ownerwg=db.Column(db.String(40),nullable=False)
    logtime=db.Column(db.DateTime,default=datetime.fromtimestamp)
    changetype=db.Column(db.String(20),nullable=False)
    changestatus=db.Column(db.String(20),nullable=False)
    urgency=db.Column(db.String(10),nullable=False)
    operationalrisk=db.Column(db.String(10),nullable=False)
    assignedworkgroup=db.Column(db.String(30),nullable=False)
    downtimerequired=db.Column(db.String(10),nullable=False)
    plannedstarttime=db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    plannedendtime=db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    summary=db.Column(db.String(400),nullable=False)
    description=db.Column(db.String(400), nullable=False)
    businessimpact=db.Column(db.String(100), nullable=False)
    impactedservices=db.Column(db.String(100), nullable=False)
    backoutplan=db.Column(db.String(100), nullable=False)
    backoutplantested=db.Column(db.String(10), nullable=False)
    actualstarttime=db.Column(db.DateTime)
    actualendtime=db.Column(db.DateTime)
    changeimplementedstatus=db.Column(db.String(25))
    changesuccessstatus=db.Column(db.String(15))
    solution=db.Column(db.String(200))
    wgoapprovalstatus=db.Column(db.String(50))
    cmapprovalstatus=db.Column(db.String(50))
    nextstatus=db.Column(db.String(40))

    def __init__(self,requester, requesterid, ownerwg, logtime, changetype, changestatus, urgency, operationalrisk, assignedworkgroup, downtimerequired, plannedstarttime, plannedendtime, summary, description, businessimpact, impactedservices, backoutplan, backoutplantested, actualstarttime, actualendtime, changeimplementedstatus, changesuccessstatus, solution, wgoapprovalstatus, cmapprovalstatus, nextstatus ):
        self.requester = requester
        self.requesterid = requesterid
        self.ownerwg = ownerwg
        self.logtime = logtime
        self.changetype = changetype
        self.changestatus = changestatus
        self.urgency = urgency
        self.operationalrisk = operationalrisk
        self.assignedworkgroup = assignedworkgroup
        self.downtimerequired = downtimerequired
        self.plannedstarttime = plannedstarttime
        self.plannedendtime = plannedendtime
        self.summary = summary
        self.description = description
        self.businessimpact = businessimpact
        self.impactedservices = impactedservices
        self.backoutplan = backoutplan
        self.backoutplantested = backoutplantested
        self.actualstarttime = actualstarttime
        self.actualendtime = actualendtime
        self.changeimplementedstatus = changeimplementedstatus
        self.changesuccessstatus = changesuccessstatus
        self.solution = solution
        self.wgoapprovalstatus = wgoapprovalstatus
        self.cmapprovalstatus = cmapprovalstatus
        self.nextstatus = nextstatus



with app.app_context():
    db.create_all()

def validate_credentials():
    username_val=User.query.filter_by(username=request.form['username_u']).first()
    if username_val:
        if username_val.mobile == request.form['phonenumber_u']:
            return True
        else:
            return render_template('index.html', username_val=username_val)

def valdiateStatus(change_r):
    if change_r.changestatus == "Requested" and change_r.wgoapprovalStatus =="Approved":
        return 'Pending for Approval'
    elif change_r.changestatus == "Pending for Approval" and change_r.cmapprovalStatus=="Approved":
        return 'Approved'
       

def validate_user_name():
    existing_user_name = User.query.filter_by(username=request.form['InputUserName']).first()
    if existing_user_name:
        raise ValidationError(
            "Username already exists please select diifferent username"
        )
    else:
        return True


@app.route("/", methods=['GET','POST'])
def Login():
    if request.method == 'POST':
        username=request.form['InputUserName']
        password=request.form['Input_Password']
        errors = []
        if not username:
            errors.append('Enter Username')
        if not password:
            errors.append('Enter Password')

        if errors:
            return render_template("Index.html", errors=errors)
        else:
            user=User.query.filter_by(username=request.form['InputUserName']).first()
            if user:
                if bcrypt.check_password_hash(user.password, password):
                    success_msg="Successfully Logged in"
                    login_user(user)
                    return render_template("Home.html", success_msg=success_msg)
                else:
                    return render_template("Index.html", errors_login="Invalid Username/Password")
                
            
    return render_template('Index.html')

def statuscheck(cr):
    change_r = Change_Table.query.filter_by(cr=cr).first()
    if change_r.changestatus == "Referred Back":
        return "Requested"
    if change_r.changestatus == "Requested":
        return "Requested"
    if change_r.changestatus == "Pending for Approval":
        return "Pending for Approval"
    if change_r.changestatus == "Approved":
        return "Approved"
    if change_r.changestatus == "In-Progress":
        return "In-Progress"
    if change_r.changestatus == "Implemented":
        return "Implemented"

def nextstatus(cr):
    change_r=Change_Table.query.filter_by(cr=cr).first()
    changestatus = request.form['changestatus']
    if changestatus == "Requested":
        return "Cancelled"
    elif changestatus == "Pending For Approval":
        return "Cancelled"
    elif changestatus == "Approved":
        return "In Progress"
    elif changestatus == "In Progress":
        return "Implemented"
    
@app.route('/changerecord/<int:cr>', methods=['GET', 'POST'])
@login_required
def Change_Record(cr):
    if request.method == 'POST':
        errors=[]
        ownerworkgroup=request.form['ownerworkgroupv']
        changetype=request.form['changetype']
        changestatus=request.form['changestatus']
        urgency=request.form['urgency']
        operationalrisk=request.form['operationalrisk']
        assignedworkgroup=request.form['assignedworkgroup']
        downtimerequired=request.form['downtimerequired']
        plannedstarttime=request.form['plannedstarttime']
        plannedendtime=request.form['plannedendtime']
        summary=request.form['summary']
        description=request.form['description']
        businessimpact=request.form['businessimpact']
        impactedservices=request.form['impactedservices']
        backoutplan=request.form['backoutplan']
        backoutplantested=request.form['backoutplantested']
        actualstarttime=request.form['actualstarttime']
        actualendtime=request.form['actualendtime']
        changeimplementedstatus=request.form['changeimplementedstatus']
        changesuccessstatus=request.form['changesuccessstatus']
        solution=request.form['solution']
                
        if not ownerworkgroup:
            errors.append('Owner Workgroup not updated')
        if not changetype:
            errors.append('Change Type not updated')
        if not changestatus:
            errors.append('Change Staus not updated')
        if not urgency:
            errors.append('Urgency not updated')
        if not operationalrisk:
            errors.append('Operational Risk not updated')
        if not assignedworkgroup:
            errors.append('Assigned Workgroup not updated')
        if not downtimerequired:
            errors.append('Downtime Required not updated')
        if not plannedstarttime:
            errors.append('Field not updated')
        if not plannedendtime:
            errors.append('Planned End Time not updated')
        if not summary:
            errors.append('Summary not updated')
        if not description:
            errors.append('Description not updated')
        if not businessimpact:
            errors.append('Business Impact Services not updated')
        if not impactedservices:
            errors.append('Impacted Services not updated')
        if not backoutplan:
            errors.append('Backout Plan not updated')
        if not backoutplantested:
            errors.append('Backout Plan Tested not updated')
            
        if errors:
            return render_template('change_record.html', errors="Please update all fields in General and Risk Tab", change_r=change_r)
        else:
            change_r = Change_Table.query.filter_by(cr=cr).first()

            change_r.urgency=urgency
            change_r.operationalrisk=operationalrisk
            change_r.assignedworkgroup=assignedworkgroup
            change_r.downtimerequired=downtimerequired
            change_r.plannedstarttime=plannedstarttime
            change_r.plannedendtime=plannedendtime
            change_r.summary=summary
            change_r.description=description
            change_r.businessimpact=businessimpact
            change_r.impactedservices=impactedservices
            change_r.backoutplan=backoutplan
            change_r.backoutplantested=backoutplantested
            change_r.actualstarttime=actualstarttime
            change_r.actualendtime=actualendtime
            change_r.changeimplementedstatus=changeimplementedstatus
            change_r.changesuccessstatus=changesuccessstatus
            change_r.solution=solution
            
            change_r.changestatus=changestatus
            change_r.nextstatus=nextstatus(cr)
            

            db.session.add(change_r)
            db.session.commit()
            
            if current_user.team == "Change Management":
                return render_template('change_ar.html', change_r=change_r)
            elif current_user.team == assignedworkgroup and current_user.role=="Workgroup Owner":
                return render_template("change_ar.html", change_r=change_r)
            else:
                return render_template("change_record.html", change_r=change_r)
    else:
        change_r = Change_Table.query.filter_by(cr=cr).first()
        if current_user.team == "Change Management":
            return render_template("change_ar.html", change_r=change_r)
        elif current_user.team == change_r.assignedworkgroup and current_user.role=="Workgroup Owner":
            return render_template("change_ar.html", change_r=change_r)
        else:
            return render_template("change_record.html", change_r=change_r)

@app.route("/search", methods=['GET', 'POST'])
@login_required
def Search():
    if request.method=='POST':
        change_s = request.form['inputChangeNumber']
        search_c=request.form['flexRadioDefault']
        change_r=Change_Table.query.filter_by(cr=change_s).first()
        if search_c == "Change":
            if change_r:
                if current_user.team == "Change Management":
                    return render_template("change_ar.html", change_r=change_r)
                elif current_user.team == change_r.assignedworkgroup and current_user.role=="Workgroup Owner":
                    return render_template("change_ar.html", change_r=change_r)
                else:
                    return render_template("change_record.html", change_r=change_r)
            else:
                change_rr=Change_Table.query.all()
                return render_template("view_change.html", change_r=change_rr, errors="Record Not Found")

@app.route("/approverfc/<int:cr>", methods=['GET', 'POST'])
def ApproveRFC(cr):
    if request.method=='POST':
        astatus=request.form['approvalwg']
        acomments=request.form['comments']
        change_r=Change_Table.query.filter_by(cr=cr).first()
        if change_r.changestatus == "Requested":
            if astatus == "Approve":
                if current_user.team == change_r.assignedworkgroup:
                    change_r.wgoapprovalstatus="Approved"
                    change_r.changestatus="Pending For Approval"
                    change_r.nextstatus="Cancelled"
                    db.session.add(change_r)
                    db.session.commit()

                    return render_template("change_ar.html", change_r=change_r, success_msg="RFC Approved !! Please check with change management team for final approval")
                else:
                    return render_template("change_ar.html", change_r=change_r, errors="You are not authorized to approve the change. Please wait for workgroup owner approval")
            elif astatus =="reffer back":
                if current_user.team == change_r.assignedworkgroup:
                    change_r.wgoapprovalstatus="Reffered Back"
                    change_r.changestatus="Reffered Back"
                    change_r.nextstatus="Cancelled"
                    db.session.add(change_r)
                    db.session.commit()
                    return render_template("change_ar.html", change_r=change_r, success_msg="RFC Referred Back !!")
                else:
                    return render_template("change_ar.html", change_r=change_r, errors="You are not authorized to update the change status. Please wait for workgroup owner approval")
        elif change_r.changestatus == "Pending For Approval":
            if astatus == "Approve":
                if current_user.team == "Change Management":
                    change_r.cmapprovalstatus="Approved"
                    change_r.changestatus="Approved"
                    change_r.nextstatus="In Progress"
                    db.session.add(change_r)
                    db.session.commit()
                    return render_template("change_ar.html", change_r=change_r, success_msg="RFC Approved !!")
                else:
                    return render_template("change_ar.html", change_r=change_r, errors="You are not authorized to approve the change.")
            elif astatus =="reffer back":
                if current_user.team == "Change Management":
                    change_r.cmapprovalstatus="Reffered Back"
                    change_r.changestatus="Reffered Back"
                    change_r.nextstatus="Cancelled"
                    db.session.add(change_r)
                    db.session.commit()
                    return render_template("change_ar.html", change_r=change_r, success_msg="RFC Referred Back !!")
                else:
                    return render_template("change_ar.html", change_r=change_r, errors="You are not authorized to update the change status. Please wait for workgroup owner approval")

@app.route('/changear/<int:cr>', methods=['GET', 'POST'])
@login_required
def Change_AR(cr):
    if request.method == 'POST':
        errors=[]
        ownerworkgroup=request.form['ownerworkgroupv']
        changetype=request.form['changetype']
        changestatus=request.form['changestatus']
        urgency=request.form['urgency']
        operationalrisk=request.form['operationalrisk']
        assignedworkgroup=request.form['assignedworkgroup']
        downtimerequired=request.form['downtimerequired']
        plannedstarttime=request.form['plannedstarttime']
        plannedendtime=request.form['plannedendtime']
        summary=request.form['summary']
        description=request.form['description']
        businessimpact=request.form['businessimpact']
        impactedservices=request.form['impactedservices']
        backoutplan=request.form['backoutplan']
        backoutplantested=request.form['backoutplantested']
        actualstarttime=request.form['actualstarttime']
        actualendtime=request.form['actualendtime']
        changeimplementedstatus=request.form['changeimplementedstatus']
        changesuccessstatus=request.form['changesuccessstatus']
        solution=request.form['solution']

        if not ownerworkgroup:
            errors.append('Owner Workgroup not updated')
        if not changetype:
            errors.append('Change Type not updated')
        if not changestatus:
            errors.append('Change Staus not updated')
        if not urgency:
            errors.append('Urgency not updated')
        if not operationalrisk:
            errors.append('Operational Risk not updated')
        if not assignedworkgroup:
            errors.append('Assigned Workgroup not updated')
        if not downtimerequired:
            errors.append('Downtime Required not updated')
        if not plannedstarttime:
            errors.append('Field not updated')
        if not plannedendtime:
            errors.append('Planned End Time not updated')
        if not summary:
            errors.append('Summary not updated')
        if not description:
            errors.append('Description not updated')
        if not businessimpact:
            errors.append('Business Impact Services not updated')
        if not impactedservices:
            errors.append('Impacted Services not updated')
        if not backoutplan:
            errors.append('Backout Plan not updated')
        if not backoutplantested:
            errors.append('Backout Plan Tested not updated')
   
        
        change_r = Change_Table.query.filter_by(cr=cr).first()
        
        change_r.urgency=urgency
        change_r.operationalrisk=operationalrisk
        change_r.assignedworkgroup=assignedworkgroup
        change_r.downtimerequired=downtimerequired
        change_r.plannedstarttime=plannedstarttime
        change_r.plannedendtime=plannedendtime
        change_r.summary=summary
        change_r.description=description
        change_r.businessimpact=businessimpact
        change_r.impactedservices=impactedservices
        change_r.backoutplan=backoutplan
        change_r.backoutplantested=backoutplantested
        change_r.actualstarttime=actualstarttime
        change_r.actualendtime=actualendtime
        change_r.changeimplementedstatus=changeimplementedstatus
        change_r.changesuccessstatus=changesuccessstatus
        change_r.solution=solution
        
        
        db.session.add(change_r)
        db.session.commit()
        return render_template('change_ar.html', change_r=change_r, success="Successfully updated Change record" )
    else:
        change_r = Change_Table.query.filter_by(cr=cr).first()
        return render_template("change_ar.html", change_r=change_r)    


@app.route("/change", methods=['GET', 'POST'])
@login_required
def Change():
    if request.method=='POST':
        errors=[]
        ownerworkgroup=request.form['ownerworkgroup']
        logtime=datetime.now()
        changetype=request.form['changetype']
        urgency=request.form['urgency']
        operationalrisk=request.form['operationalrisk']
        assignedworkgroup=request.form['assignedworkgroup']
        downtimerequired=request.form['downtimerequired']
        plannedstarttime=request.form['plannedstarttime']
        plannedendtime=request.form['plannedendtime']
        summary=request.form['summary']
        description=request.form['description']
        businessimpact=request.form['businessimpact']
        impactedservices=request.form['impactedservices']
        backoutplan=request.form['backoutplan']
        backoutplantested=request.form['backoutplantested']
        actualstarttime=request.form['actualstarttime']
        actualendtime=request.form['actualendtime']
        changeimplementedstatus=request.form['changeimplementedstatus']
        changesuccessstatus=request.form['changesuccessstatus']
        solution=request.form['solution']
        wgoapprovalstatus=''
        cmapprovalstatus=''
        if not ownerworkgroup:
            errors.append('Owner Workgroup not updated')
        if not changetype:
            errors.append('Change Type not updated')
        if not urgency:
            errors.append('Urgency not updated')
        if not operationalrisk:
            errors.append('Operational Risk not updated')
        if not assignedworkgroup:
            errors.append('Assigned Workgroup not updated')
        if not downtimerequired:
            errors.append('Downtime Required not updated')
        if not plannedstarttime:
            errors.append('Field not updated')
        if not plannedendtime:
            errors.append('Planned End Time not updated')
        if not summary:
            errors.append('Summary not updated')
        if not description:
            errors.append('Description not updated')
        if not businessimpact:
            errors.append('Business Impact Services not updated')
        if not impactedservices:
            errors.append('Impacted Services not updated')
        if not backoutplan:
            errors.append('Backout Plan not updated')
        if not backoutplantested:
            errors.append('Backout Plan Tested not updated')
        
        if errors:
            return render_template('change.html', errors="Please update all fields in General and Risk Tab")
        else:
            reqr=current_user.id
            requester=current_user.username
            change_record=Change_Table(requester=requester,requesterid=reqr,ownerwg=ownerworkgroup,logtime=logtime,changetype=changetype,changestatus="Requested",urgency=urgency,operationalrisk=operationalrisk,assignedworkgroup=assignedworkgroup,downtimerequired=downtimerequired,plannedstarttime=plannedstarttime,plannedendtime=plannedendtime,summary=summary,description=description,businessimpact=businessimpact,impactedservices=impactedservices,backoutplan=backoutplan,backoutplantested=backoutplantested,actualstarttime=actualstarttime,actualendtime=actualendtime,changeimplementedstatus=changeimplementedstatus,changesuccessstatus=changesuccessstatus,solution=solution,wgoapprovalstatus=wgoapprovalstatus,cmapprovalstatus=cmapprovalstatus, nextstatus="Cancelled")
            db.session.add(change_record)
            db.session.commit()
            
            return render_template('change_record.html', change_r=change_record, success_msg="Successfully added RFC")
    return render_template("change.html")

@app.route("/viewchanges")
@login_required
def View_Changes():
    change_r=Change_Table.query.all()
    return render_template("view_change.html", change_r=change_r)

@app.route("/register", methods=['GET', 'POST'])
@login_required
def Register():
    if request.method == 'POST':
        if validate_user_name:
            email=request.form['InputEmail']
            username=request.form['InputUserName']
            mobile=int(request.form['InputMobile'])
            team=request.form['InputTeam']
            role=request.form['InputRole']
            hashed_password = bcrypt.generate_password_hash(request.form['InputPassword'])
            user=User(email=email, username=username, mobile=mobile, team=team, role=role, password=hashed_password)
            db.session.add(user)
            db.session.commit()
    if current_user.team == "Tools Support":
        return render_template('Register.html')
    else:
        return redirect(url_for("Home_Page"))

@app.route("/forgotpassword", methods=['GET','POST'])
def ForgotPassword():
    username = request.form['username_u']
    mobile = request.form['phonenumber_u']
    errors = []
    if not username:
        errors.append('Enter Your Username')
    if not mobile:
        errors.append('Enter Your Number')
    if not validate_credentials: 
        errors.append('Enter correct Username and Mobile Number')
    
    if errors:
        return render_template('index.html', errors=errors)
    else:
        success_msg="Password successfully updated"
        resetpassword=bcrypt.generate_password_hash(request.form['resetpassword_u'])
        updated = User.query.filter_by(username=request.form['username_u']).update(dict(password=resetpassword))
        db.session.commit()
        return render_template("index.html", success_msg=success_msg)

@app.route("/home", methods=['GET', 'POST'])
def Home_Page():
    if current_user.is_authenticated:
        return render_template("Home.html")
    else:
        return redirect(url_for('Login'))

@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('Login'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
