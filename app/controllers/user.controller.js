  
  exports.allAccess = (req, res) => {
    res.status(200).send("Public Content.");
  };
  exports.dashborad = (req, res) => {
    res.status(200).send("User Dashboard.");
  };
  
 