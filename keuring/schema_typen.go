package keuring

import "strings"

// De soorten organisatie uit schema.org: Organization, LocalBusiness en al hun
// subtypes. Eén lijst voor alle punten, zodat "Duidelijk wie je bent" en
// "Gestructureerde gegevens kloppen" hetzelfde herkennen (een AutoRepair is een
// bedrijf, ook al staat het woord Organization er niet in).

// lokaleTypen: LocalBusiness en alles daaronder. Daarbij horen een adres en een
// telefoonnummer.
var lokaleTypen = setVan(
	"LocalBusiness",
	"AnimalShelter", "ArchiveOrganization", "ChildCare", "DryCleaningOrLaundry",
	"EmploymentAgency", "InternetCafe", "Library", "ProfessionalService",
	"RadioStation", "RealEstateAgent", "RecyclingCenter", "SelfStorage",
	"ShoppingCenter", "TelevisionStation", "TouristInformationCenter", "TravelAgency",
	// auto
	"AutomotiveBusiness", "AutoBodyShop", "AutoDealer", "AutoPartsStore", "AutoRental",
	"AutoRepair", "AutoWash", "GasStation", "MotorcycleDealer", "MotorcycleRepair",
	// nood
	"EmergencyService", "FireStation", "Hospital", "PoliceStation",
	// uitgaan
	"EntertainmentBusiness", "AdultEntertainment", "AmusementPark", "ArtGallery",
	"Casino", "ComedyClub", "MovieTheater", "NightClub",
	// geld
	"FinancialService", "AccountingService", "AutomatedTeller", "BankOrCreditUnion",
	"InsuranceAgency",
	// eten en drinken
	"FoodEstablishment", "Bakery", "BarOrPub", "Brewery", "CafeOrCoffeeShop",
	"Distillery", "FastFoodRestaurant", "IceCreamShop", "Restaurant", "Winery",
	// overheid
	"GovernmentOffice", "PostOffice",
	// verzorging
	"HealthAndBeautyBusiness", "BeautySalon", "DaySpa", "HairSalon", "HealthClub",
	"NailSalon", "TattooParlor",
	// huis en bouw
	"HomeAndConstructionBusiness", "Electrician", "GeneralContractor", "HVACBusiness",
	"HousePainter", "Locksmith", "MovingCompany", "Plumber", "RoofingContractor",
	// juridisch
	"LegalService", "Attorney", "Notary",
	// overnachten
	"LodgingBusiness", "BedAndBreakfast", "Campground", "Hostel", "Hotel", "Motel",
	"Resort", "SkiResort", "VacationRental",
	// zorg
	"MedicalBusiness", "CommunityHealth", "Dentist", "Dermatology", "DietNutrition",
	"Emergency", "Geriatric", "Gynecologic", "MedicalClinic", "Midwifery", "Nursing",
	"Obstetric", "Oncologic", "Optician", "Optometric", "Otolaryngologic", "Pediatric",
	"Pharmacy", "Physician", "Physiotherapy", "PlasticSurgery", "Podiatric",
	"PrimaryCare", "Psychiatric", "PublicHealth",
	// sport
	"SportsActivityLocation", "BowlingAlley", "ExerciseGym", "GolfCourse",
	"PublicSwimmingPool", "SportsClub", "StadiumOrArena", "TennisComplex",
	// winkels
	"Store", "BikeStore", "BookStore", "ClothingStore", "ComputerStore",
	"ConvenienceStore", "DepartmentStore", "ElectronicsStore", "Florist",
	"FurnitureStore", "GardenStore", "GroceryStore", "HardwareStore", "HobbyShop",
	"HomeGoodsStore", "JewelryStore", "LiquorStore", "MensClothingStore",
	"MobilePhoneStore", "MovieRentalStore", "MusicStore", "OfficeEquipmentStore",
	"OutletStore", "PawnShop", "PetStore", "ShoeStore", "SportingGoodsStore",
	"TireShop", "ToyStore", "WholesaleStore",
)

// andereOrganisaties: organisaties die geen LocalBusiness zijn, zoals een
// webwinkel, school of vereniging. Daar is geen adres verplicht.
var andereOrganisaties = setVan(
	"Organization", "Airline", "Consortium", "Cooperative", "Corporation",
	"EducationalOrganization", "CollegeOrUniversity", "ElementarySchool", "HighSchool",
	"MiddleSchool", "Preschool", "School", "FundingScheme", "GovernmentOrganization",
	"LibrarySystem", "MedicalOrganization", "DiagnosticLab", "VeterinaryCare", "NGO",
	"NewsMediaOrganization", "OnlineBusiness", "OnlineStore", "PerformingGroup",
	"DanceGroup", "MusicGroup", "TheaterGroup", "PoliticalParty", "Project",
	"FundingAgency", "ResearchProject", "ResearchOrganization",
	"SearchRescueOrganization", "SportsOrganization", "SportsTeam", "WorkersUnion",
)

func setVan(namen ...string) map[string]bool {
	m := make(map[string]bool, len(namen))
	for _, n := range namen {
		m[strings.ToLower(n)] = true
	}
	return m
}

// kaalType haalt het voorvoegsel weg: "https://schema.org/AutoRepair" en
// "schema:AutoRepair" worden "autorepair".
func kaalType(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.LastIndexAny(t, "/:#"); i >= 0 {
		t = t[i+1:]
	}
	return strings.ToLower(t)
}

// lokaalType: LocalBusiness of een subtype daarvan.
func lokaalType(t string) bool { return lokaleTypen[kaalType(t)] }

// organisatieType: Organization, LocalBusiness of een subtype van een van beide.
func organisatieType(t string) bool {
	k := kaalType(t)
	return lokaleTypen[k] || andereOrganisaties[k]
}
