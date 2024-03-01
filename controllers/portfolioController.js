const PortfolioItem = require('../models/PortfolioItem');

exports.addPortfolioItem = async (req, res) => {
    try {
        const newItem = new PortfolioItem(req.body);
        await newItem.save();
        res.redirect('/admin/dashboard');
    } catch (error) {
        res.status(500).send('Server error');
    }
};

exports.getPortfolioItems = async (req, res) => {
    try {
        const items = await PortfolioItem.find();
        res.render('admin/dashboard', { items });
    } catch (error) {
        res.status(500).send('Server error');
    }
};

exports.editPortfolioItem = async (req, res) => {
    try {
        const { id } = req.params;
        await PortfolioItem.findByIdAndUpdate(id, req.body);
        res.redirect('/admin/dashboard');
    } catch (error) {
        res.status(500).send('Server error');
    }
};

exports.deletePortfolioItem = async (req, res) => {
    try {
        const { id } = req.params;
        await PortfolioItem.findByIdAndDelete(id);
        res.redirect('/admin/dashboard');
    } catch (error) {
        res.status(500).send('Server error');
    }
};
