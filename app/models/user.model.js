const mongoose=require('mongoose')

const userSchema=new mongoose.Schema({
    

    username:{
        type:String,
        uninque:true,
        required:true,
        
    },

    email:{
        type:String,
        uninque:true,
        required:true, 
    },

    password:{
        type:String,
        required:true, 
    },

    cpassword:{
        type:String,
        required:true, 
    },
   
},{
    timestamps:true,
});

module.exports =mongoose.model('User',userSchema);
